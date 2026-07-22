package selfrecursion_test

// Spike #575 Step 2 (empirical, part 1): re-exposure probe.
//
// Step 1's decisive claim (from a read-trace) was: after self-recursion, the only
// columns left with Proof status (i.e. emitted to the verifier, where a mask would be
// re-exposed) are the Merkle roots and the SIS digests CollapsedSisHashQ / Edual —
// while Ualpha and the opened columns are flipped to Committed (hidden in the next
// layer's witness). If true, a mask placed on Ualpha / the opened columns is preserved
// (re-buried), not re-exposed.
//
// This test compiles ONE self-recursion layer and enumerates the actual Proof-status
// columns, so the claim is checked against the real compiled circuit rather than a
// code-read. It asserts nothing yet beyond "no Ualpha/opened column is Proof"; its
// primary value is the printed census (run with -v).

import (
	"strings"
	"testing"

	"github.com/consensys/linea-monorepo/prover/protocol/compiler"
	"github.com/consensys/linea-monorepo/prover/protocol/compiler/dummy"
	"github.com/consensys/linea-monorepo/prover/protocol/compiler/poseidon2"
	"github.com/consensys/linea-monorepo/prover/protocol/compiler/selfrecursion"
	"github.com/consensys/linea-monorepo/prover/protocol/compiler/vortex"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/sirupsen/logrus"
)

// TestMaskSurvivalMultiLayer settles the terminal-artifact question: with a REAL next
// vortex layer (not dummy) above the self-recursion, do layer-0's opened columns
// (VORTEX_0_SELECTED_COL_...) become Committed (hidden inside layer 1)? If yes, the
// single-layer test's "opened columns are Proof" was purely the dummy terminal exposing
// them, and self-recursion + a real next layer DOES re-bury them — the Step-1 claim,
// now with the correct (multi-hop) test shape.
func TestMaskSurvivalMultiLayer(t *testing.T) {
	logrus.SetLevel(logrus.FatalLevel)

	tc := TestCase{Numpoly: 32, NumRound: 3, PolSize: 32, NumOpenCol: 16, SisInstance: sisInstances[0]}
	define, _ := generateProtocol(tc)

	comp := wizard.Compile(
		define,
		vortex.Compile(2, false, vortex.ForceNumOpenedColumns(tc.NumOpenCol), vortex.WithSISParams(&tc.SisInstance)),
		selfrecursion.SelfRecurse,
		poseidon2.CompilePoseidon2,
		compiler.Arcane(compiler.WithTargetColSize(1<<10)),
		vortex.Compile(2, false, vortex.ForceNumOpenedColumns(tc.NumOpenCol), vortex.WithSISParams(&tc.SisInstance)),
		selfrecursion.SelfRecurse,
		poseidon2.CompilePoseidon2,
		compiler.Arcane(compiler.WithTargetColSize(1<<13)),
		vortex.Compile(2, false, vortex.ForceNumOpenedColumns(tc.NumOpenCol), vortex.WithSISParams(&tc.SisInstance)),
	)

	// Status of layer-0's opened columns: hidden by layer 1, or still Proof?
	proof := map[string]bool{}
	for _, id := range comp.Columns.AllKeysProof() {
		proof[string(id)] = true
	}
	var layer0OpenedStillProof []string
	for _, id := range comp.Columns.AllKeys() {
		s := string(id)
		if strings.Contains(s, "VORTEX_0_SELECTED_COL") && proof[s] {
			layer0OpenedStillProof = append(layer0OpenedStillProof, s)
		}
	}
	t.Logf("layer-0 opened columns still Proof after a REAL next layer: %d", len(layer0OpenedStillProof))
	for _, s := range layer0OpenedStillProof {
		t.Logf("  still-Proof: %s", s)
	}
	if len(layer0OpenedStillProof) == 0 {
		t.Logf("CONFIRMED: layer-0 opened columns are Committed (hidden) once a real next layer exists — single-layer Proof was the dummy terminal. Step-1 boundary claim holds.")
	} else {
		t.Logf("NUANCE: some layer-0 opened columns remain Proof even with a real next layer — needs cryptographer review of whether these leak.")
	}
}

func TestMaskSurvivalReExposureProbe(t *testing.T) {
	logrus.SetLevel(logrus.FatalLevel)

	tc := TestCase{Numpoly: 32, NumRound: 3, PolSize: 32, NumOpenCol: 16, SisInstance: sisInstances[0]}
	define, _ := generateProtocol(tc)

	comp := wizard.Compile(
		define,
		vortex.Compile(
			2,
			false,
			vortex.ForceNumOpenedColumns(16),
			vortex.WithSISParams(&tc.SisInstance),
		),
		selfrecursion.SelfRecurse,
		dummy.Compile,
	)

	proofCols := comp.Columns.AllKeysProof()

	// Categorize by name so the census is readable. These substrings match the
	// column IDs the selfrecursion package assigns (Ualpha, OpenedColumns/opening,
	// the SIS residues, and the Merkle roots).
	buckets := map[string]int{}
	var ualphaOrOpened []string
	for _, id := range proofCols {
		s := string(id)
		low := strings.ToLower(s)
		switch {
		case strings.Contains(low, "ualpha"):
			buckets["Ualpha (SHOULD be Committed, not Proof)"]++
			ualphaOrOpened = append(ualphaOrOpened, s)
		case strings.Contains(low, "opencol") || strings.Contains(low, "opened") || strings.Contains(low, "selectedcol"):
			buckets["OpenedColumns (SHOULD be Committed)"]++
			ualphaOrOpened = append(ualphaOrOpened, s)
		case strings.Contains(low, "collapse") || strings.Contains(low, "sishash") || strings.Contains(low, "edual"):
			buckets["SIS residues CollapsedSisHashQ/Edual (expected Proof)"]++
		case strings.Contains(low, "root") || strings.Contains(low, "merkle"):
			buckets["Merkle roots (expected Proof)"]++
		default:
			buckets["other: "+s]++
		}
	}

	t.Logf("=== self-recursion Proof-status column census (%d total) ===", len(proofCols))
	for k, v := range buckets {
		t.Logf("  %3d  %s", v, k)
	}

	t.Logf("=== flagged Ualpha/opened column EXACT names (are they original layer-A, or selfrecursion-internal?) ===")
	for _, s := range ualphaOrOpened {
		t.Logf("  FLAGGED: %s", s)
	}
	// Also dump every Proof col containing SELECTED_COL / SELECTED (the opened columns),
	// since the underscore made them miss the bucket above.
	t.Logf("=== all Proof cols matching SELECTED (opened columns) ===")
	for _, id := range proofCols {
		if strings.Contains(string(id), "SELECTED") {
			t.Logf("  SELECTED: %s", string(id))
		}
	}
}
