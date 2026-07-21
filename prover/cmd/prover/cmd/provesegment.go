package cmd

import (
	"fmt"

	"github.com/consensys/linea-monorepo/prover/config"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/distributed"
	"github.com/consensys/linea-monorepo/prover/protocol/serde"
	"github.com/consensys/linea-monorepo/prover/zkevm"
	"github.com/sirupsen/logrus"
)

// ProveSegmentArgs holds the arguments for the `prove-segment` worker command.
type ProveSegmentArgs struct {
	ConfigFile  string
	Kind        string // "GL" or "LPP"
	Witness     string // path to the module witness shipped by the coordinator
	SharedRand  string // LPP only: path to the serialized shared-randomness octuplet
	Out         string // path to write the serialized SegmentProof (to ship back)
}

// ProveSegment (POC, multi-node worker) proves ONE limitless segment on this machine
// from a witness file shipped by the coordinator, and writes the serialized SegmentProof
// to disk to ship back. It reuses the exact single-segment prover the in-process pipeline
// uses (RunGL/RunLPP -> RecursedSegmentCompilation.ProveSegmentKoala), so a segment proved
// on a worker node is identical to one proved locally.
//
// GL segments need only the witness + the compiled GL circuit for their module. LPP
// segments additionally need the shared-randomness octuplet the coordinator derived from
// ALL GL segment proofs (the GL->LPP barrier), stamped into InitialFiatShamirState.
func ProveSegment(args ProveSegmentArgs) error {
	cfg, err := config.NewConfigFromFile(args.ConfigFile)
	if err != nil {
		return fmt.Errorf("prove-segment: read config %v: %w", args.ConfigFile, err)
	}

	var proof *distributed.SegmentProof

	switch args.Kind {
	case "GL":
		witness := &distributed.ModuleWitnessGL{}
		wbuf, err := serde.LoadFromDiskMmapBacked(args.Witness, witness)
		if err != nil {
			return fmt.Errorf("prove-segment GL: load witness %v: %w", args.Witness, err)
		}
		moduleName := string([]byte(witness.ModuleName)) // heap copy before mmap release
		logrus.Infof("prove-segment GL: module=%s", moduleName)
		compiled, cbuf, err := zkevm.LoadCompiledGLMmap(cfg, distributed.ModuleName(moduleName))
		if err != nil {
			wbuf.Release()
			return fmt.Errorf("prove-segment GL: load compiled circuit (module=%s): %w", moduleName, err)
		}
		proof = compiled.ProveSegmentKoala(witness).ClearRuntime()
		wbuf.Release()
		cbuf.Release()

	case "LPP":
		witness := &distributed.ModuleWitnessLPP{}
		wbuf, err := serde.LoadFromDiskMmapBacked(args.Witness, witness)
		if err != nil {
			return fmt.Errorf("prove-segment LPP: load witness %v: %w", args.Witness, err)
		}
		// Inject the shared randomness the coordinator derived from all GL proofs.
		var sr field.Octuplet
		closer, err := serde.LoadFromDisk(args.SharedRand, &sr, false)
		if err != nil {
			wbuf.Release()
			return fmt.Errorf("prove-segment LPP: load shared randomness %v: %w", args.SharedRand, err)
		}
		closer.Close()
		witness.InitialFiatShamirState = sr
		moduleName := string([]byte(witness.ModuleName))
		logrus.Infof("prove-segment LPP: module=%s", moduleName)
		compiled, cbuf, err := zkevm.LoadCompiledLPPMmap(cfg, distributed.ModuleName(moduleName))
		if err != nil {
			wbuf.Release()
			return fmt.Errorf("prove-segment LPP: load compiled circuit (module=%s): %w", moduleName, err)
		}
		proof = compiled.ProveSegmentKoala(witness).ClearRuntime()
		wbuf.Release()
		cbuf.Release()

	default:
		return fmt.Errorf("prove-segment: unknown --kind %q (want GL or LPP)", args.Kind)
	}

	// Write the proof compressed to shrink the wire (each SegmentProof is multi-GB raw).
	if err := serde.StoreToDisk(args.Out, *proof, true); err != nil {
		return fmt.Errorf("prove-segment: write proof %v: %w", args.Out, err)
	}
	logrus.Infof("prove-segment: wrote SegmentProof to %s (%s segment)", args.Out, args.Kind)
	return nil
}
