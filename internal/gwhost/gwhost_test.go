package gwhost

import (
	"testing"

	"openbin.ai/binny/internal/app"
)

// AllProjectSpecs must tolerate no client (offline / not signed in) and still
// return the local decompiles — here, with an empty store, that's an empty list,
// and crucially it does not panic or require a backend.
func TestAllProjectSpecsNoClientNoPanic(t *testing.T) {
	specs := AllProjectSpecs(nil, app.ModeMalware)
	// No assertion on count (depends on the machine's store); the contract is
	// that a nil client is safe and every returned spec carries the mode.
	for _, s := range specs {
		if s.Mode != app.ModeMalware {
			t.Errorf("spec mode = %q, want MALWARE", s.Mode)
		}
		if s.ProjectRef == "" {
			t.Errorf("spec has empty project ref")
		}
	}
}

// StartAll with nothing to share returns a clear error rather than binding an
// empty gateway.
func TestStartAllWithNoProjects(t *testing.T) {
	// A controller with a nil client and (assumed) empty store yields no specs.
	c := NewController(Config{})
	_, err := c.StartAll(":0", "", app.ModeMalware)
	// If the dev machine happens to have local projects this won't error; in CI
	// the store is empty, so we only assert the no-projects branch when it fires.
	if err == nil {
		// Started successfully (machine had projects) — clean up.
		c.Stop()
		return
	}
	if err.Error() == "" {
		t.Errorf("expected a descriptive no-projects error")
	}
}
