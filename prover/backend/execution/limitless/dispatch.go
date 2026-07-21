package limitless

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/consensys/linea-monorepo/prover/config"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/distributed"
	"github.com/consensys/linea-monorepo/prover/protocol/serde"
	"github.com/sirupsen/logrus"
)

// Multi-node segment dispatch (POC). When LIMITLESS_REMOTE_WORKER is set, the GL/LPP
// segment indices listed in LIMITLESS_REMOTE_GL / LIMITLESS_REMOTE_LPP are proved on a
// remote worker instead of locally: the coordinator ships the module witness over, runs
// `prover-poc prove-segment` there, ships the SegmentProof back, and deserializes it into
// the same in-process pipeline. Transport is scp+ssh (a POC — a real build would use a
// persistent RPC/queue). Unset LIMITLESS_REMOTE_WORKER => everything proves locally
// (default, the single-node path is untouched).
//
// Env:
//   LIMITLESS_REMOTE_WORKER  comma list of ssh hosts (e.g. "node2" or "node2,work-hp");
//                            empty disables dispatch
//   LIMITLESS_REMOTE_GL      GL segment indices to send remote. Either a flat comma list
//                            ("1,4" — all go to the first worker), or per-worker groups
//                            "node2:2,3;work-hp:4,5"
//   LIMITLESS_REMOTE_LPP     LPP segment indices, same syntax as LIMITLESS_REMOTE_GL
//   LIMITLESS_REMOTE_DIR     remote working dir (default /tmp/prover-remote, same on all workers)
//   LIMITLESS_REMOTE_CONFIG  config path on the workers (points at each worker's local assets;
//                            same path on all workers)
//   LIMITLESS_REMOTE_BIN     prover binary path on the workers (default "prover-poc")

func remoteWorkers() []string {
	v := os.Getenv("LIMITLESS_REMOTE_WORKER")
	if v == "" {
		return nil
	}
	var ws []string
	for _, w := range strings.Split(v, ",") {
		if w = strings.TrimSpace(w); w != "" {
			ws = append(ws, w)
		}
	}
	return ws
}

func remoteDir() string {
	if d := os.Getenv("LIMITLESS_REMOTE_DIR"); d != "" {
		return d
	}
	return "/tmp/prover-remote"
}

func remoteConfig() string { return os.Getenv("LIMITLESS_REMOTE_CONFIG") }

func remoteBin() string {
	if b := os.Getenv("LIMITLESS_REMOTE_BIN"); b != "" {
		return b
	}
	return "prover-poc"
}

// workerFor returns the ssh host that segment index i of the given kind ("GL"/"LPP") is
// assigned to via LIMITLESS_REMOTE_<KIND>, or "" if the segment proves locally. The spec
// is either a flat comma list of indices ("2,3" — all assigned to the first worker) or
// semicolon-separated per-worker groups ("node2:2,3;work-hp:4,5").
func workerFor(kind string, i int) string {
	workers := remoteWorkers()
	if len(workers) == 0 {
		return ""
	}
	for _, group := range strings.Split(os.Getenv("LIMITLESS_REMOTE_"+kind), ";") {
		worker, list := workers[0], group
		if c := strings.IndexByte(group, ':'); c >= 0 {
			worker, list = strings.TrimSpace(group[:c]), group[c+1:]
		}
		for _, s := range strings.Split(list, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n == i {
				return worker
			}
		}
	}
	return ""
}

// Separate concurrency caps for local vs remote proving. The nodes can only prove ~1
// segment at a time without swap-thrashing, so with JOBS>=2 (needed to overlap local
// proving with a blocking remote dispatch) we must independently limit how many segments
// prove locally vs remotely. LIMITLESS_LOCAL_CONCURRENCY caps local proves,
// LIMITLESS_REMOTE_CONCURRENCY caps how many segments EACH worker proves at once (not the
// total across workers). Unset => no cap (the errgroup's JOBS limit alone applies, i.e.
// default single-node behavior unchanged).
var localSem = makeSem("LIMITLESS_LOCAL_CONCURRENCY")

var (
	remoteSemsOnce sync.Once
	remoteSems     map[string]chan struct{}
)

// remoteSemFor returns the concurrency semaphore for the given worker (nil => no cap).
func remoteSemFor(worker string) chan struct{} {
	remoteSemsOnce.Do(func() {
		remoteSems = make(map[string]chan struct{})
		for _, w := range remoteWorkers() {
			remoteSems[w] = makeSem("LIMITLESS_REMOTE_CONCURRENCY")
		}
	})
	return remoteSems[worker]
}

func makeSem(env string) chan struct{} {
	if v := os.Getenv(env); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return make(chan struct{}, n)
		}
	}
	return nil
}

func acquire(s chan struct{}) {
	if s != nil {
		s <- struct{}{}
	}
}

func release(s chan struct{}) {
	if s != nil {
		<-s
	}
}

// runGLDispatch proves GL segment i locally, or remotely if it is assigned to a worker.
func runGLDispatch(cfg *config.Config, i int, cache *circuitCache) (*distributed.SegmentProof, error) {
	if w := workerFor("GL", i); w != "" {
		sem := remoteSemFor(w)
		acquire(sem)
		defer release(sem)
		return runSegmentRemote(cfg, w, "GL", i, nil)
	}
	acquire(localSem)
	defer release(localSem)
	return RunGL(cfg, i, cache)
}

// runLPPDispatch proves LPP segment i locally, or remotely if assigned to a worker.
// sr is the shared randomness the coordinator derived from all GL proofs (the barrier).
func runLPPDispatch(cfg *config.Config, i int, sr field.Octuplet) (*distributed.SegmentProof, error) {
	if w := workerFor("LPP", i); w != "" {
		sem := remoteSemFor(w)
		acquire(sem)
		defer release(sem)
		return runSegmentRemote(cfg, w, "LPP", i, &sr)
	}
	acquire(localSem)
	defer release(localSem)
	return RunLPP(cfg, i, sr)
}

// runSegmentRemote ships witness-<kind>-<i> to the given worker, runs prove-segment
// there, ships the SegmentProof back, and deserializes it. sr is the shared-randomness
// octuplet (LPP only; nil for GL). The returned proof is bit-identical to a locally-proved
// one, so it flows into the shared-randomness barrier and conglomeration unchanged.
func runSegmentRemote(cfg *config.Config, worker, kind string, i int, sr *field.Octuplet) (*distributed.SegmentProof, error) {
	rdir := remoteDir()
	localWitness := fmt.Sprintf("%s/witness-%s-%d", witnessDir, kind, i)
	remoteWitness := fmt.Sprintf("%s/witness-%s-%d", rdir, kind, i)
	remoteProof := fmt.Sprintf("%s/proof-%s-%d", rdir, kind, i)
	localProof := fmt.Sprintf("%s/proof-%s-%d", witnessDir, kind, i)

	logrus.Infof("dispatch: %s segment %d -> remote worker %s", kind, i, worker)

	// 1. ensure the remote working dir exists, then ship the witness.
	if err := runCmd("ssh", worker, "mkdir", "-p", rdir); err != nil {
		return nil, fmt.Errorf("dispatch %s-%d: mkdir remote: %w", kind, i, err)
	}
	if err := runCmd("scp", "-q", localWitness, worker+":"+remoteWitness); err != nil {
		return nil, fmt.Errorf("dispatch %s-%d: scp witness: %w", kind, i, err)
	}

	// 2. assemble the remote prove-segment invocation (LPP also ships shared randomness).
	remoteCmd := []string{remoteBin(), "prove-segment", "--config", remoteConfig(),
		"--kind", kind, "--witness", remoteWitness, "--out", remoteProof}
	if kind == "LPP" {
		if sr == nil {
			return nil, fmt.Errorf("dispatch LPP-%d: nil shared randomness", i)
		}
		localSR := fmt.Sprintf("%s/sharedrand", witnessDir)
		remoteSR := fmt.Sprintf("%s/sharedrand", rdir)
		if err := serde.StoreToDisk(localSR, *sr, false); err != nil {
			return nil, fmt.Errorf("dispatch LPP-%d: store shared randomness: %w", i, err)
		}
		if err := runCmd("scp", "-q", localSR, worker+":"+remoteSR); err != nil {
			return nil, fmt.Errorf("dispatch LPP-%d: scp shared randomness: %w", i, err)
		}
		remoteCmd = append(remoteCmd, "--shared-randomness", remoteSR)
	}

	// 3. prove the segment on the worker.
	if err := runCmd("ssh", worker, strings.Join(remoteCmd, " ")); err != nil {
		return nil, fmt.Errorf("dispatch %s-%d: remote prove-segment: %w", kind, i, err)
	}

	// 4. ship the proof back and deserialize (the worker wrote it compressed).
	if err := runCmd("scp", "-q", worker+":"+remoteProof, localProof); err != nil {
		return nil, fmt.Errorf("dispatch %s-%d: scp proof back: %w", kind, i, err)
	}
	var proof distributed.SegmentProof
	closer, err := serde.LoadFromDisk(localProof, &proof, true)
	if err != nil {
		return nil, fmt.Errorf("dispatch %s-%d: load returned proof: %w", kind, i, err)
	}
	closer.Close()
	logrus.Infof("dispatch: %s segment %d proved remotely and collected", kind, i)
	return &proof, nil
}

// runCmd runs an external command, folding stderr into the error on failure.
func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w — %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
