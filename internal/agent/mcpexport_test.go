package agent

import (
	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/tools"
	"testing"
)

// The MCP exports must register exactly the Docker-backed tools, by the same
// names the TUI/Desktop use. Registration is Docker-free (the container is built
// lazily on first call), so this runs anywhere.

func TestRegisterSandboxToolsAddsExpectedTools(t *testing.T) {
	reg := tools.NewRegistry()
	RegisterSandboxTools(reg, &app.Session{SamplePath: "/tmp/sample.bin"})
	for _, name := range []string{"write_file", "run", "read_artifact"} {
		if !reg.Has(name) {
			t.Errorf("sandbox tool %q not registered", name)
		}
	}
}

func TestRegisterDecompileToolAddsTool(t *testing.T) {
	reg := tools.NewRegistry()
	proj := &api.Project{ID: "local:abc123", Kind: api.KindBIN, Name: "x"}
	tb := tools.NewToolbox(nil, proj)
	RegisterDecompileTool(reg, &app.Session{Project: proj, SamplePath: "/tmp/sample.bin"}, tb, func(string, ...any) {})
	if !reg.Has("decompile_sample") {
		t.Errorf("decompile_sample not registered")
	}
}

// With no sample attached, the sandbox tools are still registered (so the host
// model sees the capability) and return an actionable error at call time rather
// than silently missing. This mirrors BINNY's own behavior.
func TestSandboxToolsRegisteredEvenWithoutSample(t *testing.T) {
	reg := tools.NewRegistry()
	RegisterSandboxTools(reg, &app.Session{})
	if !reg.Has("run") {
		t.Fatalf("run tool should be registered even without a sample")
	}
}
