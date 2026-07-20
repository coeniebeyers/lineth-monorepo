package cmd

import (
	"fmt"

	"github.com/consensys/linea-monorepo/prover/config"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/distributed"
	"github.com/consensys/linea-monorepo/prover/protocol/serde"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/zkevm"
	"github.com/sirupsen/logrus"
)

// VerifyArgs holds the arguments for the `verify` command.
type VerifyArgs struct {
	Proof      string
	ConfigFile string
}

// Verify (POC) checks a pre-wrap conglomeration proof (emitted by
// `prove --stop-before-wrap`) using Linea's native wizard verifier. It loads
// the conglomeration compiled IOP asset (produced by `setup`, referenced via
// the same config/assets_dir as prove) and the serialized proof, then runs the
// full wizard.Verify against RecursionCompBLS.
//
// Soundness: after wizard.Verify (internal validity + the terminal BLS Vortex
// opening), it natively re-runs the wrap-only COMPLETENESS checks
// (checkConglomerationCompleteness) — VK-merkle-root pin, all-segments-present,
// global-accumulator cancellation and shared-randomness — so an incomplete or
// wrong-VK conglomeration is rejected. It does NOT yet bind the functional public
// inputs (state root / block number) to a settlement statement; that binding is
// the remaining follow-up.
func Verify(args VerifyArgs) error {
	cfg, err := config.NewConfigFromFile(args.ConfigFile)
	if err != nil {
		return fmt.Errorf("verify: read config file at %v: %w", args.ConfigFile, err)
	}

	// Load the conglomeration compiled IOP (a setup asset). The mmap buffer is
	// zero-copy — it must stay alive until after Verify, so release on return.
	cong, buf, err := zkevm.LoadCompiledConglomerationMmap(cfg)
	if err != nil {
		return fmt.Errorf("verify: load conglomeration asset: %w", err)
	}
	defer buf.Release()

	// Load the serialized pre-wrap proof (uncompressed, matching the emit path).
	// The deserialized proof points into its mmap; keep the closer open until
	// after Verify.
	var proof wizard.Proof
	closer, err := serde.LoadFromDisk(args.Proof, &proof, false)
	if err != nil {
		return fmt.Errorf("verify: load proof %v: %w", args.Proof, err)
	}
	defer closer.Close()

	// 1. Verify the pre-wrap conglomeration proof (internal validity + the terminal
	//    BLS Vortex opening). VerifyWithRuntime returns the runtime so we can read
	//    the proof's public inputs for the completeness checks below.
	run, err := wizard.VerifyWithRuntime(cong.RecursionCompBLS, proof, true)
	if err != nil {
		return fmt.Errorf("PROOF INVALID: %w", err)
	}

	// 2. Re-run the wrap-only completeness checks natively (Tier-1). wizard.Verify
	//    alone is relational and accepts an incomplete/wrong-VK conglomeration. The
	//    trusted VK-merkle-root comes from a SEPARATE setup asset (not the proof);
	//    the conglomeration VK octuplets come from the compiled IOP's ExtraData.
	vkTree, err := zkevm.LoadVerificationKeyMerkleTree(cfg)
	if err != nil {
		return fmt.Errorf("verify: load VK merkle tree: %w", err)
	}
	trustedVKRoot := vkTree.GetRoot()

	var congVK0, congVK1 *field.Octuplet
	if raw0, ok0 := cong.RecursionCompBLS.ExtraData[distributed.VerifyingKeyPublicInput]; ok0 {
		if raw1, ok1 := cong.RecursionCompBLS.ExtraData[distributed.VerifyingKey2PublicInput]; ok1 {
			if v0, k0 := raw0.(field.Octuplet); k0 {
				if v1, k1 := raw1.(field.Octuplet); k1 {
					congVK0, congVK1 = &v0, &v1
				}
			}
		}
	}
	if congVK0 == nil {
		logrus.Warn("verify: conglomeration VK not in ExtraData — skipping self-VK pin (VK-merkle-root pin still enforced)")
	}

	if err := checkConglomerationCompleteness(run, trustedVKRoot, congVK0, congVK1); err != nil {
		return fmt.Errorf("PROOF INCOMPLETE: %w", err)
	}

	logrus.Infof("PROOF VALID + COMPLETE: %s", args.Proof)
	return nil
}
