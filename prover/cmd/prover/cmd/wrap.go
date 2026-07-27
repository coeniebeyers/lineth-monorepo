package cmd

import (
	"fmt"
	"time"

	"github.com/consensys/linea-monorepo/prover/backend/execution"
	"github.com/consensys/linea-monorepo/prover/circuits"
	execCirc "github.com/consensys/linea-monorepo/prover/circuits/execution"
	"github.com/consensys/linea-monorepo/prover/config"
	"github.com/consensys/linea-monorepo/prover/protocol/serde"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/utils/signal"
	"github.com/consensys/linea-monorepo/prover/zkevm"
	"github.com/sirupsen/logrus"
)

// WrapArgs holds the arguments for the `wrap` command.
type WrapArgs struct {
	// Input is the original execution (getZkProof) request the pre-wrap proof
	// was proved from. It is re-parsed to rebuild the functional public inputs
	// and exec data the wrap circuit binds to.
	Input string
	// Proof is the pre-wrap conglomeration proof emitted by
	// `prove --stop-before-wrap`.
	Proof string
	// Output is where the standard execution response (wrapped proof included)
	// is written.
	Output     string
	ConfigFile string
}

// Wrap (POC) runs the final BLS12-377 PLONK wrap from a pre-wrap conglomeration
// proof emitted by `prove --stop-before-wrap`, decoupling the wrap from the
// distributed pipeline so it can run later and/or on a different (big-RAM) box.
//
// It rebuilds the functional inputs and exec data from the original execution
// request exactly like the prove path does (CraftProverOutput + NewWitness —
// pure request parsing, no trace files and no proving), loads the emitted proof
// and the conglomeration compiled IOP, loads the outer-circuit setup, then runs
// the very same execCirc.MakeProof call the pipeline runs after conglomeration
// and writes the standard execution response to --out.
//
// Memory: loading the outer setup (constraint system + proving key + BLS12-377
// SRS) is the ~191GB step that stop-before-wrap skips — only run this command
// on a box sized for the wrap. Setup-load and wrap-proof wall times are logged
// separately so the two costs can be benchmarked on their own.
func Wrap(args WrapArgs) error {

	// This allows the user to dump stacktraces by sending a SIGUSR1 to the
	// current process.
	signal.RegisterStackTraceDumpHandler()

	// Fail fast on missing arguments before touching any asset.
	if args.Input == "" || args.Proof == "" || args.Output == "" {
		return fmt.Errorf("wrap: --in, --proof and --out are all required")
	}

	cfg, err := config.NewConfigFromFile(args.ConfigFile)
	if err != nil {
		return fmt.Errorf("wrap: read config file at %v: %w", args.ConfigFile, err)
	}

	// Rebuild the functional public inputs and exec data from the original
	// execution request — the same values the pipeline passes to MakeProof.
	req := &execution.Request{}
	if err := readRequest(args.Input, req); err != nil {
		return fmt.Errorf("wrap: read the request file (%v): %w", args.Input, err)
	}
	var (
		out     = execution.CraftProverOutput(cfg, req)
		witness = execution.NewWitness(cfg, req, &out)
	)

	// Load the serialized pre-wrap proof (uncompressed, matching the emit path)
	// BEFORE the fat setup, so a bad path fails in seconds rather than after a
	// long setup load. The deserialized proof points into its mmap; keep the
	// closer open until after MakeProof.
	var proof wizard.Proof
	closer, err := serde.LoadFromDisk(args.Proof, &proof, false)
	if err != nil {
		return fmt.Errorf("wrap: load pre-wrap proof %v: %w", args.Proof, err)
	}
	defer closer.Close()

	// Load the conglomeration compiled IOP (RecursionCompBLS is the wizard the
	// outer circuit verifies). The mmap buffer is zero-copy — it must stay
	// alive until after MakeProof, so release on return.
	cong, congBuf, err := zkevm.LoadCompiledConglomerationMmap(cfg)
	if err != nil {
		return fmt.Errorf("wrap: load conglomeration asset: %w", err)
	}
	defer congBuf.Release()

	// Load the outer-circuit setup (constraint system + proving key + SRS). In
	// the pipeline this load overlaps proving; here it runs sequentially so its
	// wall time is measured on its own.
	logrus.Infof("Loading setup - circuitID: %s", circuits.ExecutionLimitlessCircuitID)
	setupStart := time.Now()
	setup, err := circuits.LoadSetup(cfg, circuits.ExecutionLimitlessCircuitID)
	if err != nil {
		return fmt.Errorf("wrap: load setup: %w", err)
	}
	logrus.Infof("wrap: setup load took %s", time.Since(setupStart))

	// Run exactly the same wrap step the pipeline runs after conglomeration.
	wrapStart := time.Now()
	out.Proof = execCirc.MakeProof(
		&cfg.TracesLimits,
		setup,
		cong.RecursionCompBLS,
		proof,
		*witness.FuncInp,
		witness.ZkEVM.ExecData,
	)
	logrus.Infof("wrap: wrap proof took %s", time.Since(wrapStart))

	out.VerifyingKeyShaSum = setup.VerifyingKeyDigest()

	return writeResponse(args.Output, &out)
}
