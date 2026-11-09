package main

// `binny mcp` — serve BINNY's reverse-engineering tools over the Model Context
// Protocol (stdio), so an MCP host (a Hermes computer, Claude Desktop, any MCP
// client) can drive them against one project. The host's model is the analyst;
// BINNY supplies the tools and the project they read.
//
// Phase 1 scope: the READ toolset (list_functions, get_function, get_strings,
// get_imports, xrefs, reachability, decompiled-source reads, manifest/code
// search for APKs). The local-decompile and sandbox `run` tools — which need
// Docker on the host — and BINNY's own investigate/report loop are deliberately
// out of scope here; see the integration notes.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/auth"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/mcp"
	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/tools"
)

// runMCP implements the `binny mcp` subcommand.
func runMCP(args []string) error {
	fs := flag.NewFlagSet("binny mcp", flag.ContinueOnError)
	project := fs.String("project", "", "project to serve: a backend project id, a local id (local:<sha>), or the sha of a local decompile")
	list := fs.Bool("list", false, "list projects reachable with the current sign-in and exit")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: binny mcp --project <id> [flags]

Serves BINNY's reverse-engineering tools for one project over the Model Context
Protocol on stdio (newline-delimited JSON-RPC). An MCP host spawns this command
and its model drives the tools; diagnostics go to stderr, never stdout.

  binny mcp --list                     list projects you can open
  binny mcp --project <backend-id>     serve a cloud OpenBin/OpenAPK project
  binny mcp --project local:<sha12>    serve a locally decompiled project
  binny mcp --project <sha>            same, by the sample's sha

Backend projects need 'openbin login'. Local projects come from 'binny'/'binny
desktop' '/decompile' and are read from disk.

Register it on a Hermes profile as a stdio MCP server, e.g.:
  command: binny
  args:    ["mcp", "--project", "local:abc123def456"]

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	ep := config.LoadEndpoints()
	toks, err := auth.NewTokenSource(ep)
	if err != nil {
		return fmt.Errorf("auth: %w (run 'openbin login' first for backend projects)", err)
	}
	client := api.New(ep, toks)

	if *list {
		return listProjects(client)
	}
	if strings.TrimSpace(*project) == "" {
		fs.Usage()
		return fmt.Errorf("missing --project (use 'binny mcp --list' to see what's available)")
	}

	proj, err := resolveProject(client, *project)
	if err != nil {
		return err
	}

	// Build the read toolset over the project. This is the same Toolbox the TUI
	// and Desktop use; local APK/script trees are resolved from the on-disk
	// store automatically by the toolbox, so no extra wiring is needed here.
	reg := tools.NewRegistry()
	tb := tools.NewToolbox(client, proj)
	tb.Progress = func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "binny: "+format+"\n", args...)
	}
	tb.RegisterRead(reg)

	srv := mcp.NewServer(reg, version)
	srv.Logf = func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "binny mcp: "+format+"\n", args...)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Fprintf(os.Stderr, "binny mcp: serving %s (%s, %s) over stdio — %d tools\n",
		proj.Name, proj.Kind, proj.ID, len(reg.Names()))
	return srv.Serve(ctx, os.Stdin, os.Stdout)
}

// resolveProject turns the --project flag into an attached *api.Project. It
// accepts a backend id, an explicit "local:<sha>" id, or a bare sha that names
// a local decompile in the on-disk store.
func resolveProject(client *api.Client, ref string) (*api.Project, error) {
	ref = strings.TrimSpace(ref)

	// Explicit local id, or a bare sha that exists in the local store.
	if strings.HasPrefix(ref, store.LocalIDPrefix) {
		sha := strings.TrimPrefix(ref, store.LocalIDPrefix)
		return loadLocalProject(sha)
	}
	if looksLikeSha(ref) {
		if meta, err := store.Load(ref); err == nil {
			return localProjectFromMeta(*meta), nil
		}
		// Not in the local store — fall through and try it as a backend id.
	}

	proj, err := client.GetProject(ref)
	if err != nil {
		return nil, fmt.Errorf("open project %q: %w (is it a backend id you can access, or a local sha? try 'binny mcp --list')", ref, err)
	}
	return proj, nil
}

func loadLocalProject(sha string) (*api.Project, error) {
	meta, err := store.Load(sha)
	if err != nil {
		return nil, fmt.Errorf("no local project for %q: %w (decompile it first with 'binny' /decompile)", sha, err)
	}
	return localProjectFromMeta(*meta), nil
}

// looksLikeSha reports whether ref is plausibly a hex sample hash (so we try the
// local store before the backend). Local ids are 12+ hex chars.
func looksLikeSha(ref string) bool {
	if len(ref) < 8 {
		return false
	}
	for _, c := range ref {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// localProjectFromMeta synthesizes the api.Project a stored local analysis
// attaches as. Mirrors the TUI's (unexported) localProject so the read tools
// serve the on-disk analysis/tree identically.
func localProjectFromMeta(meta store.Meta) *api.Project {
	if meta.Kind == store.KindAPK {
		return &api.Project{
			ID:               store.LocalID(meta.Sha256),
			Kind:             api.KindAPK,
			Name:             meta.Name,
			OriginalFilename: meta.Name,
			SizeBytes:        meta.SizeBytes,
			Sha256:           meta.Sha256,
			Status:           "READY",
			AnalysisMode:     "MALWARE",
			PackageName:      meta.PackageName,
			CreatedAt:        meta.CreatedAt,
		}
	}
	arch := meta.Processor
	if arch == "" {
		arch = meta.Language
	}
	return &api.Project{
		ID:               store.LocalID(meta.Sha256),
		Kind:             api.KindBIN,
		Name:             meta.Name,
		OriginalFilename: meta.Name,
		SizeBytes:        meta.SizeBytes,
		Sha256:           meta.Sha256,
		Status:           "READY",
		AnalysisMode:     "MALWARE",
		Arch:             arch,
		ExecutableFormat: meta.Format,
		LanguageID:       meta.Language,
		CreatedAt:        meta.CreatedAt,
	}
}

// listProjects prints local decompiles and backend projects so the user can
// copy an id into --project. Backend listing failures are reported but don't
// stop the local listing (you may be offline / not signed in).
func listProjects(client *api.Client) error {
	locals := store.List()
	if len(locals) > 0 {
		fmt.Println("Local projects (served from disk):")
		for _, m := range locals {
			kind := "BIN"
			if m.Kind == store.KindAPK {
				kind = "APK"
			}
			fmt.Printf("  %-22s  %-3s  %s\n", store.LocalID(m.Sha256), kind, m.Name)
		}
		fmt.Println()
	}

	projects, err := client.ListProjects()
	if err != nil {
		fmt.Fprintf(os.Stderr, "binny mcp: couldn't list backend projects: %v\n", err)
		if len(locals) == 0 {
			return err
		}
		return nil
	}
	if len(projects) == 0 {
		if len(locals) == 0 {
			fmt.Println("No projects found. Decompile one with 'binny' /decompile, or open one at openbin.ai.")
		}
		return nil
	}
	fmt.Println("Backend projects (OpenBin / OpenAPK):")
	for _, p := range projects {
		fmt.Printf("  %-22s  %-3s  %-8s  %s\n", p.ID, p.Kind, p.Status, p.Name)
	}
	return nil
}
