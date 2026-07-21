package distributed_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/consensys/linea-monorepo/prover/backend/execution/limitless"
	"github.com/consensys/linea-monorepo/prover/config"
	"github.com/consensys/linea-monorepo/prover/protocol/distributed"
	"github.com/consensys/linea-monorepo/prover/protocol/serde"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
)

// TestConglomerationDiskSpill exercises the opt-in disk-spill (streaming)
// conglomeration. It checks two things:
//
//  1. a segment proof round-trips losslessly through the spill serde path, in
//     both the compressed (heap) and uncompressed (mmap) modes the queue uses; and
//  2. RunConglomerationHierarchical with spill enabled and the resident budget
//     forced to 1 — so every proof beyond the first is written to disk and loaded
//     back just-in-time — aggregates the segments into a valid final proof.
//
// The final-proof check is validity, not byte-equality: the merge order is
// non-deterministic (concurrent LIFO workers), so different runs may build
// different merge trees, but a corrupted spill would fail a merge's constraint
// check and hard-exit the process. A clean, non-nil result therefore means the
// spilled-then-loaded proofs merged exactly as resident ones would.
func TestConglomerationDiskSpill(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy conglomeration test in short mode")
	}

	const numRow = 1 << 5
	tc := &LookupTestCase{numRow: numRow}

	// Produce real GL + LPP segment proofs (mirrors runConglomerationWizardTest).
	comp := wizard.Compile(func(build *wizard.Builder) { tc.Define(build.CompiledIOP) })
	disc := &distributed.StandardModuleDiscoverer{TargetWeight: 3 * numRow / 2, Advices: tc.Advices()}
	distWizard := distributed.DistributeWizard(comp, disc).
		CompileSegments(testCompilationParams).
		Conglomerate(testCompilationParams)
	runtimeBoot := wizard.RunProver(distWizard.Bootstrapper, tc.Assign, false)
	witnessGLs, witnessLPPs := distributed.SegmentRuntime(
		runtimeBoot, distWizard.Disc, distWizard.BlueprintGLs, distWizard.BlueprintLPPs,
		distWizard.VerificationKeyMerkleTree.GetRoot(),
	)
	glProofs := runProverGLs(t, distWizard, witnessGLs)
	sharedRandomness := distributed.GetSharedRandomnessFromSegmentProofs(glProofs)
	lppProofs := runProverLPPs(t, distWizard, sharedRandomness, witnessLPPs)

	allProofs := append(append([]*distributed.SegmentProof{}, glProofs...), lppProofs...)
	if len(allProofs) < 2 {
		t.Fatalf("need >= 2 segment proofs to conglomerate, got %d", len(allProofs))
	}

	// (1) The spill/load round-trip preserves the proof.
	//
	// NOTE: we deliberately do NOT compare raw serialized bytes. wizard.Proof holds
	// map-backed collections (Messages / QueriesParams, collection.Mapping) and Go
	// randomises map iteration order, so two serializations of the *same* proof come
	// out byte-different while being logically identical (observed: equal length,
	// differing bytes). We therefore compare the deterministic identity + witness
	// shape + serialized size, and rely on (2) — a conglomeration fed entirely from
	// spilled proofs — as the end-to-end correctness proof.
	orig := allProofs[0]
	origBytes, err := serde.Serialize(*orig)
	if err != nil {
		t.Fatalf("serialize original: %v", err)
	}
	for _, compress := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "seg.bin")
		if err := serde.StoreToDisk(path, *orig, compress); err != nil {
			t.Fatalf("StoreToDisk (compress=%v): %v", compress, err)
		}
		var loaded distributed.SegmentProof
		closer, err := serde.LoadFromDisk(path, &loaded, compress)
		if err != nil {
			t.Fatalf("LoadFromDisk (compress=%v): %v", compress, err)
		}
		if loaded.ProofType != orig.ProofType || loaded.ModuleIndex != orig.ModuleIndex ||
			loaded.SegmentIndex != orig.SegmentIndex || loaded.LppCommitment != orig.LppCommitment {
			closer.Close()
			t.Fatalf("spill round-trip changed proof identity (compress=%v): got type=%v mod=%d seg=%d, want type=%v mod=%d seg=%d",
				compress, loaded.ProofType, loaded.ModuleIndex, loaded.SegmentIndex,
				orig.ProofType, orig.ModuleIndex, orig.SegmentIndex)
		}
		if got, want := len(loaded.RecursionWitness.Pub), len(orig.RecursionWitness.Pub); got != want {
			closer.Close()
			t.Fatalf("spill round-trip lost public inputs (compress=%v): %d vs %d", compress, got, want)
		}
		if got, want := len(loaded.RecursionWitness.CommittedMatrices), len(orig.RecursionWitness.CommittedMatrices); got != want {
			closer.Close()
			t.Fatalf("spill round-trip lost committed matrices (compress=%v): %d vs %d", compress, got, want)
		}
		if loaded.RecursionWitness.FinalFS != orig.RecursionWitness.FinalFS {
			closer.Close()
			t.Fatalf("spill round-trip changed the final Fiat-Shamir state (compress=%v)", compress)
		}
		back, err := serde.Serialize(loaded)
		if err != nil {
			closer.Close()
			t.Fatalf("serialize round-tripped: %v", err)
		}
		if len(back) != len(origBytes) {
			closer.Close()
			t.Fatalf("spill round-trip changed serialized size (compress=%v): %d vs %d bytes", compress, len(back), len(origBytes))
		}
		closer.Close()
	}
	t.Logf("spill/load round-trip preserved proof identity, witness shape and serialized size (compress true + false)")

	// (2) End-to-end: conglomerate with spill ENABLED and every proof forced to
	// disk (resident budget = 1). A non-nil result with no error/exit means the
	// spilled-then-loaded proofs merged into a valid final proof.
	t.Setenv("LIMITLESS_MERGE_RESIDENT_MAX", "1")
	cfg := &config.Config{}
	cfg.Execution.ConglomerationSpillDir = t.TempDir()
	spill, err := limitless.ResolveSpillPolicy(cfg)
	if err != nil {
		t.Fatalf("ResolveSpillPolicy: %v", err)
	}

	ch := make(chan *distributed.SegmentProof, len(allProofs))
	for _, p := range allProofs {
		ch <- p
	}
	close(ch)

	spilledBefore := limitless.SpilledProofCount()
	final, err := limitless.RunConglomerationHierarchical(
		context.Background(),
		&distWizard.VerificationKeyMerkleTree,
		distWizard.CompiledConglomeration,
		ch, len(allProofs), spill,
	)
	if err != nil {
		t.Fatalf("spill-enabled conglomeration failed: %v", err)
	}
	if final == nil {
		t.Fatal("spill-enabled conglomeration returned a nil final proof")
	}

	// A valid final proof alone does NOT prove the spill path ran: if the resident
	// budget never bites (the accounting bug the first real-scale run exposed —
	// merge workers held proofs outside the budget), the run silently degrades to
	// the everything-in-RAM path and this test passes vacuously. Spill files are
	// deleted as merges consume them, so assert via the process-wide spill counter.
	spilled := limitless.SpilledProofCount() - spilledBefore
	if spilled == 0 {
		t.Fatal("spill-enabled conglomeration with residentMax=1 never spilled a proof to disk — the resident budget is not being enforced")
	}
	t.Logf("spill-enabled conglomeration merged %d segments (%d spilled to disk) into a valid final proof", len(allProofs), spilled)
}
