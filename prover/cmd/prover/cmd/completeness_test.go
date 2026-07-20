package cmd

import (
	"fmt"
	"testing"

	msethash "github.com/consensys/linea-monorepo/prover/crypto/multisethashing_koalabear"
	poseidon2 "github.com/consensys/linea-monorepo/prover/crypto/poseidon2_koalabear"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/maths/field/fext"
	"github.com/consensys/linea-monorepo/prover/protocol/distributed"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
)

// stubRuntime satisfies wizard.Runtime by embedding the interface (nil underlying)
// and implementing only the two methods checkConglomerationCompleteness uses:
// GetPublicInput and GetSpec. Any other Runtime method would nil-panic, but the
// checker never calls them — which is exactly why the checker takes wizard.Runtime.
type stubRuntime struct {
	wizard.Runtime
	pubs map[string]fext.GenericFieldElem
	spec *wizard.CompiledIOP
}

func (s stubRuntime) GetPublicInput(name string) fext.GenericFieldElem { return s.pubs[name] }
func (s stubRuntime) GetSpec() *wizard.CompiledIOP                     { return s.spec }

func fe(v uint64) field.Element {
	var e field.Element
	e.SetUint64(v)
	return e
}

func extPI(e fext.Element) fext.GenericFieldElem {
	return fext.GenericFieldElem{Ext: e, IsBase: false}
}

// completePIs builds a self-consistent, COMPLETE public-input set for one module
// (numModule = 1): all segment counts equal, all multisets cancel, accumulators at
// their terminals, shared randomness = Poseidon2(sharedRandMSet), and the VK pins
// equal the supplied trusted octuplets. checkConglomerationCompleteness must accept it.
func completePIs(vkRoot, vk0, vk1 field.Octuplet) map[string]fext.GenericFieldElem {
	m := map[string]fext.GenericFieldElem{}
	n := fe(3) // segment count per module
	m[distributed.TargetNbSegmentPublicInputBase+"_0"] = fext.NewGenFieldFromBase(n)
	m[distributed.SegmentCountGLPublicInputBase+"_0"] = fext.NewGenFieldFromBase(n)
	m[distributed.SegmentCountLPPPublicInputBase+"_0"] = fext.NewGenFieldFromBase(n)

	sharedRand := make([]field.Element, msethash.MSetHashSize)
	zero := fe(0)
	for k := 0; k < msethash.MSetHashSize; k++ {
		m[fmt.Sprintf("%s_%d", distributed.GeneralMultiSetPublicInputBase, k)] = fext.NewGenFieldFromBase(zero)
		m[fmt.Sprintf("%s_%d", distributed.SharedRandomnessMultiSetPublicInputBase, k)] = fext.NewGenFieldFromBase(zero)
		sharedRand[k] = zero
	}
	rand := poseidon2.HashVec(sharedRand...)
	for i := 0; i < 8; i++ {
		m[fmt.Sprintf("%s_%d", distributed.InitialRandomnessPublicInput, i)] = fext.NewGenFieldFromBase(rand[i])
		m[fmt.Sprintf("%s_%d", distributed.VerifyingKeyMerkleRootPublicInput, i)] = fext.NewGenFieldFromBase(vkRoot[i])
		m[fmt.Sprintf("%s_%d", distributed.VerifyingKeyPublicInput, i)] = fext.NewGenFieldFromBase(vk0[i])
		m[fmt.Sprintf("%s_%d", distributed.VerifyingKey2PublicInput, i)] = fext.NewGenFieldFromBase(vk1[i])
	}
	m[distributed.LogDerivativeSumPublicInput] = extPI(fext.Zero())
	m[distributed.GrandProductPublicInput] = extPI(fext.One())
	m[distributed.HornerPublicInput] = extPI(fext.Zero())
	return m
}

func TestConglomerationCompleteness(t *testing.T) {
	var vkRoot, vk0, vk1 field.Octuplet
	for i := 0; i < 8; i++ {
		vkRoot[i] = fe(uint64(10 + i))
		vk0[i] = fe(uint64(20 + i))
		vk1[i] = fe(uint64(30 + i))
	}
	spec := &wizard.CompiledIOP{
		PublicInputs: []wizard.PublicInput{{Name: distributed.TargetNbSegmentPublicInputBase + "_0"}},
	}

	// Positive: a complete, self-consistent proof must pass.
	if err := checkConglomerationCompleteness(
		stubRuntime{pubs: completePIs(vkRoot, vk0, vk1), spec: spec}, vkRoot, &vk0, &vk1,
	); err != nil {
		t.Fatalf("complete proof should pass, got: %v", err)
	}

	// Negative: perturbing exactly ONE terminal must be rejected. One row per check.
	cases := []struct {
		name string
		key  string
		val  fext.GenericFieldElem
	}{
		{"dropped segment (GL count)", distributed.SegmentCountGLPublicInputBase + "_0", fext.NewGenFieldFromBase(fe(2))},
		{"general multiset != 0", distributed.GeneralMultiSetPublicInputBase + "_0", fext.NewGenFieldFromBase(fe(1))},
		{"grand-product != 1", distributed.GrandProductPublicInput, extPI(fext.Zero())},
		{"log-derivative != 0", distributed.LogDerivativeSumPublicInput, extPI(fext.One())},
		{"horner != 0", distributed.HornerPublicInput, extPI(fext.One())},
		{"shared randomness forged", distributed.InitialRandomnessPublicInput + "_0", fext.NewGenFieldFromBase(fe(999))},
		{"VK-merkle-root mismatch (untrusted VK set)", distributed.VerifyingKeyMerkleRootPublicInput + "_0", fext.NewGenFieldFromBase(fe(999))},
		{"self-VK mismatch", distributed.VerifyingKeyPublicInput + "_0", fext.NewGenFieldFromBase(fe(999))},
	}
	for _, c := range cases {
		m := completePIs(vkRoot, vk0, vk1)
		m[c.key] = c.val
		if err := checkConglomerationCompleteness(stubRuntime{pubs: m, spec: spec}, vkRoot, &vk0, &vk1); err == nil {
			t.Errorf("[%s] expected REJECTION, got nil (a bad proof would be accepted)", c.name)
		} else {
			t.Logf("[%s] correctly rejected: %v", c.name, err)
		}
	}
}
