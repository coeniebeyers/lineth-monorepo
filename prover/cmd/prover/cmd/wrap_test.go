package cmd

import (
	"strings"
	"testing"
)

// TestWrapArgumentWiring checks the wrap command fails fast and cleanly on bad
// arguments, before any proving asset is touched. It deliberately never gets
// past the config read — loading real setups is far too heavy for a unit test.
func TestWrapArgumentWiring(t *testing.T) {

	// Missing --in/--proof/--out is rejected up front.
	err := Wrap(WrapArgs{ConfigFile: "does-not-matter.toml"})
	if err == nil || !strings.Contains(err.Error(), "--in, --proof and --out") {
		t.Fatalf("expected a missing-argument error, got: %v", err)
	}

	// A missing config file is reported as such (and nothing heavier runs).
	err = Wrap(WrapArgs{
		Input:      "req.json",
		Proof:      "proof.wizproof",
		Output:     "resp.json",
		ConfigFile: "/nonexistent/config.toml",
	})
	if err == nil || !strings.Contains(err.Error(), "read config file") {
		t.Fatalf("expected a config-file error, got: %v", err)
	}
}
