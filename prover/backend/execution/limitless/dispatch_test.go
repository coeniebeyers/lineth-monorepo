package limitless

import "testing"

// TestWorkerFor covers the two LIMITLESS_REMOTE_<KIND> assignment syntaxes: the flat
// comma list (backward compatible — all indices go to the first worker) and the
// per-worker "host:idx,idx;host:idx" groups used for multi-worker dispatch.
func TestWorkerFor(t *testing.T) {
	t.Setenv("LIMITLESS_REMOTE_WORKER", "node2,work-hp")
	t.Setenv("LIMITLESS_REMOTE_GL", "node2:2,3;work-hp:4,5")
	t.Setenv("LIMITLESS_REMOTE_LPP", "2,4")

	cases := []struct {
		kind string
		i    int
		want string
	}{
		{"GL", 2, "node2"},
		{"GL", 3, "node2"},
		{"GL", 4, "work-hp"},
		{"GL", 5, "work-hp"},
		{"GL", 0, ""},  // unassigned -> local
		{"GL", 1, ""},  // unassigned -> local
		{"LPP", 2, "node2"}, // flat list -> first worker
		{"LPP", 4, "node2"},
		{"LPP", 3, ""},
	}
	for _, c := range cases {
		if got := workerFor(c.kind, c.i); got != c.want {
			t.Errorf("workerFor(%s, %d) = %q, want %q", c.kind, c.i, got, c.want)
		}
	}
}

// TestWorkerForDisabled checks that an empty LIMITLESS_REMOTE_WORKER disables dispatch
// entirely, regardless of stale index lists.
func TestWorkerForDisabled(t *testing.T) {
	t.Setenv("LIMITLESS_REMOTE_WORKER", "")
	t.Setenv("LIMITLESS_REMOTE_GL", "1,2,3")
	if got := workerFor("GL", 2); got != "" {
		t.Errorf("workerFor with no workers = %q, want \"\"", got)
	}
}
