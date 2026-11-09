package main

// Shared project resolution: turn a --project reference (backend id, local:<sha>,
// or a bare local-decompile sha) into an attached *api.Project. Used by the
// bighelp gateway subcommand.

import (
	"fmt"
	"strings"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/store"
)

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
