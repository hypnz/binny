package agent

// Exports for the `binny mcp` server (package main's mcp_cmd.go).
//
// The MCP server serves BINNY's tools to an external host's model instead of
// BINNY's own investigation loop, so it has no *Investigation of its own. These
// wrappers register the Docker-backed tools (sandbox + local decompile) against
// a throwaway investigation whose only job is to satisfy the artifact-recording
// calls inside the handlers. The artifacts it collects are a side effect the
// MCP host doesn't consume; the tool RESULTS (stdout, previews, decompile
// summaries) are what reach the host, exactly as in a normal session.
//
// Keeping these here — rather than reimplementing the tools in internal/tools —
// means the MCP path and the TUI/Desktop path run byte-for-byte identical
// sandbox and decompile logic, with no second copy to drift.

import (
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/ghidra"
	"openbin.ai/binny/internal/tools"
)

// RegisterSandboxTools adds write_file, run and read_artifact — the hardened
// disposable-container toolset — to reg. They read the sample path and
// workspace lazily from sess at call time, so a sample attached after start is
// picked up on the next call. Requires Docker on the host; with no sample
// attached the tools return an actionable error rather than failing to exist.
func RegisterSandboxTools(reg *tools.Registry, sess *app.Session) {
	registerSandboxTools(reg, NewInvestigation(), sess)
}

// RegisterDecompileTool adds decompile_sample — a local Ghidra headless run
// (Docker) over the attached sample — to reg, hot-swapping the result into tb
// so every read tool then serves the new analysis. logf receives the
// minutes-long progress; the MCP command points it at stderr. BIN projects
// only (APK/script projects have no native analysis to replace).
func RegisterDecompileTool(reg *tools.Registry, sess *app.Session, tb *tools.Toolbox, logf ghidra.Logf) {
	registerDecompileTool(reg, sess, tb, logf)
}
