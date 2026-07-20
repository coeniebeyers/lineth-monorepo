package cmd

import (
	"fmt"
	"strings"

	msethash "github.com/consensys/linea-monorepo/prover/crypto/multisethashing_koalabear"
	poseidon2 "github.com/consensys/linea-monorepo/prover/crypto/poseidon2_koalabear"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/distributed"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
)

// checkConglomerationCompleteness re-runs, NATIVELY, the "completeness" assertions
// that Linea's gnark wrap enforces on top of verifying the conglomeration proof
// (the in-circuit versions live in circuits/execution/builder_limitless.go:55-151).
//
// wizard.Verify on the pre-wrap conglomeration proof is purely RELATIONAL
// (protocol/distributed/conglomeration_hierarchical.go RunGnark) — it proves each
// node's public inputs are the sum/product of its children's, but never pins those
// terminals to their sound values. So a valid-but-INCOMPLETE conglomeration (a
// dropped segment, non-cancelling global sums) or one built over an attacker's
// circuit-VK set still passes wizard.Verify. This function closes that gap by
// reading the same named public inputs off the verified runtime and asserting:
//
//   - VK-merkle-root pin: the proof used OUR trusted circuit-VK set (load-bearing)
//   - all segments present: target == countGL == countLPP per module
//   - global accumulators cancel: grandProduct==1, logDeriv==0, horner==0, generalMSet==0
//   - shared randomness derived correctly: Poseidon2(sharedRandMSet) == initRandomness
//   - self-VK pins: vk0/vk1 == our trusted conglomeration VK (skipped if not supplied)
//   - multiset-op overflow bound
//
// It takes only wizard.Runtime (GetPublicInput + GetSpec) so it is unit-testable
// with a stub, and returns an error (never panics) on the first failing check.
//
// trustedVKRoot MUST be the honest VK-merkle-root the wrap would have pinned
// (loaded from the setup asset, separate from the proof). congVK0/congVK1 are the
// trusted conglomeration verifying-key octuplets (from the compiled IOP's ExtraData);
// pass nil to skip that pin when ExtraData is unavailable.
func checkConglomerationCompleteness(run wizard.Runtime, trustedVKRoot field.Octuplet, congVK0, congVK1 *field.Octuplet) error {

	// numModule: count PIs whose name contains the target-segment base
	// (mirrors builder_limitless.go:62-69 exactly — Contains, no exclusion).
	numModule := 0
	for _, pub := range run.GetSpec().PublicInputs {
		if strings.Contains(pub.Name, distributed.TargetNbSegmentPublicInputBase) {
			numModule++
		}
	}
	if numModule == 0 {
		return fmt.Errorf("completeness: no per-module segment-count public inputs found")
	}

	// Base-field lists (proof public inputs).
	target := distributed.GetPublicInputList(run, distributed.TargetNbSegmentPublicInputBase, numModule)
	countGL := distributed.GetPublicInputList(run, distributed.SegmentCountGLPublicInputBase, numModule)
	countLPP := distributed.GetPublicInputList(run, distributed.SegmentCountLPPPublicInputBase, numModule)
	generalMSet := distributed.GetPublicInputList(run, distributed.GeneralMultiSetPublicInputBase, msethash.MSetHashSize)
	sharedRandMSet := distributed.GetPublicInputList(run, distributed.SharedRandomnessMultiSetPublicInputBase, msethash.MSetHashSize)

	// (a) all segments present, and accumulate the total segment count.
	var segCount uint64
	for m := 0; m < numModule; m++ {
		if !target[m].Equal(&countGL[m]) || !target[m].Equal(&countLPP[m]) {
			return fmt.Errorf("completeness: module %d — target/GL/LPP segment counts differ (dropped or extra segment)", m)
		}
		segCount += target[m].Uint64()
	}

	// (b) multiset-op overflow bound (factor 6 per builder_limitless.go:107-116).
	if segCount*6 >= (uint64(1) << msethash.OverflowBoundBits) {
		return fmt.Errorf("completeness: multiset-op count %d exceeds overflow bound 2^%d", segCount*6, msethash.OverflowBoundBits)
	}

	// (c) general multiset cancels to zero (inter-segment "sent"=="received" boundaries).
	for k := 0; k < msethash.MSetHashSize; k++ {
		if !generalMSet[k].IsZero() {
			return fmt.Errorf("completeness: general multiset does not cancel (index %d) — inter-segment boundary mismatch", k)
		}
	}

	// (d) global accumulators reach their terminals (extension-field public inputs).
	logDeriv := run.GetPublicInput(distributed.LogDerivativeSumPublicInput).Ext
	grandProduct := run.GetPublicInput(distributed.GrandProductPublicInput).Ext
	hornerSum := run.GetPublicInput(distributed.HornerPublicInput).Ext
	if !grandProduct.IsOne() {
		return fmt.Errorf("completeness: grand-product (permutations) does not cancel to 1")
	}
	if !logDeriv.IsZero() {
		return fmt.Errorf("completeness: log-derivative sum (lookups) does not cancel to 0")
	}
	if !hornerSum.IsZero() {
		return fmt.Errorf("completeness: horner sum (projections) does not cancel to 0")
	}

	// (e) shared randomness correctly derived from all committed LPP roots
	// (same primitive as distribute.go:322).
	newRand := poseidon2.HashVec(sharedRandMSet...)
	for i := 0; i < 8; i++ {
		v := run.GetPublicInput(fmt.Sprintf("%s_%d", distributed.InitialRandomnessPublicInput, i)).Base
		if !newRand[i].Equal(&v) {
			return fmt.Errorf("completeness: shared-randomness mismatch at %d — GL<->LPP Fiat-Shamir binding forged", i)
		}
	}

	// (f) VK pins — the trust anchor. vkMerkleRoot must equal OUR trusted root; without
	// this, every check above is relational and a proof over a FOREIGN circuit-VK set
	// (e.g. a module that doesn't actually constrain the EVM) still verifies.
	for i := 0; i < 8; i++ {
		vkRoot := run.GetPublicInput(fmt.Sprintf("%s_%d", distributed.VerifyingKeyMerkleRootPublicInput, i)).Base
		if !vkRoot.Equal(&trustedVKRoot[i]) {
			return fmt.Errorf("completeness: VK-merkle-root mismatch at %d — proof built against an untrusted circuit-VK set", i)
		}
	}
	if congVK0 != nil && congVK1 != nil {
		for i := 0; i < 8; i++ {
			vk0 := run.GetPublicInput(fmt.Sprintf("%s_%d", distributed.VerifyingKeyPublicInput, i)).Base
			vk1 := run.GetPublicInput(fmt.Sprintf("%s_%d", distributed.VerifyingKey2PublicInput, i)).Base
			if !vk0.Equal(&congVK0[i]) || !vk1.Equal(&congVK1[i]) {
				return fmt.Errorf("completeness: self-VK mismatch at %d", i)
			}
		}
	}

	return nil
}
