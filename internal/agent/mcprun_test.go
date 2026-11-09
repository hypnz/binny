package agent

import (
	"strings"
	"testing"
)

func TestRenderReportWithSections(t *testing.T) {
	snap := InvestigationSnapshot{
		MalwareTypes: []string{"trojan", "infostealer"},
		Confidence:   "high",
		Sections: []ReportSection{
			{ID: "sum", Title: "Summary", Content: "A credential stealer."},
			{ID: "c2", Title: "C2", Content: "Beacons to example.test."},
		},
		IOCs: []IOC{
			{Type: "domain", Value: "example.test", EvidenceRef: "fn_beacon"},
		},
	}
	out := renderReport(snap)
	for _, want := range []string{
		"trojan, infostealer",
		"confidence high",
		"## Summary",
		"A credential stealer.",
		"## C2",
		"## Indicators of Compromise",
		"`example.test` (domain)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report missing %q\n---\n%s", want, out)
		}
	}
}

func TestRenderReportNoSectionsFallsBackToEvidence(t *testing.T) {
	// No drafted sections (stopped before synthesis) → the caller still gets the
	// evidence gathered so far, not an empty string.
	snap := InvestigationSnapshot{
		Findings: []Finding{
			{Category: "persistence", Severity: "medium", Note: "cron entry", EvidenceRefs: []string{"install_cron"}},
		},
	}
	out := renderReport(snap)
	if !strings.Contains(out, "Investigation incomplete") {
		t.Errorf("want incomplete marker, got:\n%s", out)
	}
	if !strings.Contains(out, "Evidence gathered so far") {
		t.Errorf("want evidence fallback, got:\n%s", out)
	}
}

func TestRenderReportEmptyIsStillValid(t *testing.T) {
	out := renderReport(InvestigationSnapshot{})
	if strings.TrimSpace(out) == "" {
		t.Errorf("empty snapshot should still render a non-empty placeholder")
	}
}
