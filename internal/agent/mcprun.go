package agent

// Headless driver for `binny mcp`'s investigate tool (Phase 3).
//
// Phases 1–2 hand the host's model BINNY's TOOLS. This instead runs BINNY's own
// triage → investigate → synthesize loop to a finished report and returns it, so
// the host can delegate a whole analysis ("investigate this sample") in one
// call and get BINNY's playbooks, evidence-grounding and report format back —
// not just raw tool access.
//
// It reuses the exact Engine the TUI/Desktop drive; the only difference is who
// turns the crank. We run Autonomous (no phase checkpoints, no report-shaping
// interview), extend once past a spend cap, and answer any stray ask_user with a
// proceed-on-best-judgment note so an unattended run never hangs.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/tools"
)

// InvestigateResult is the outcome of a headless run.
type InvestigateResult struct {
	Report   string                 // rendered Markdown report (BINNY's section format)
	Snapshot InvestigationSnapshot  // findings, IOCs, classification, sections, artifacts
	Stopped  string                 // non-empty if the run ended on a cap/refusal rather than a clean finish
	Rounds   int
	Tokens   int
}

// InvestigateOptions tunes a headless run. Zero values are sensible.
type InvestigateOptions struct {
	// ExtendOnCap raises the budget once and continues when a spend cap is hit,
	// instead of stopping to synthesize immediately. One extension only — an
	// unattended run must still terminate.
	ExtendOnCap bool
	// Progress receives human-readable status lines (phase changes, tool calls).
	// The MCP command points this at stderr so it shows in the host's logs. The
	// model's own streamed prose is NOT sent here (it would double the volume);
	// only transcript Lines are.
	Progress func(string)
}

// RunInvestigation builds an engine for sess and drives it to a finished report
// (or a cap/refusal stop). sess must have a Provider, Model and attached
// Project; the caller sets Autonomy to Autonomous. ctx cancellation stops the
// loop between steps and returns what was gathered so far.
func RunInvestigation(ctx context.Context, sess *app.Session, client *api.Client, opts InvestigateOptions) (*InvestigateResult, error) {
	eng, inv, err := Build(sess, client)
	if err != nil {
		return nil, err
	}
	progress := opts.Progress
	if progress == nil {
		progress = func(string) {}
	}
	// Stream the model's own prose to progress too, prefixed, so a watcher sees
	// reasoning as it happens; transcript Lines carry tool calls/results.
	eng.SetStreamSink(func(s string) { /* live token stream — intentionally quiet to avoid flooding logs */ })

	emit := func(lines []Line) {
		for _, ln := range lines {
			t := strings.TrimSpace(ln.Text)
			if t == "" {
				continue
			}
			progress(fmt.Sprintf("[%s] %s", ln.Kind, t))
		}
	}

	emit(eng.Start())

	extended := false
	for {
		if ctx.Err() != nil {
			return finish(eng, inv, "cancelled"), ctx.Err()
		}
		res := eng.Step(ctx)
		emit(res.Lines)

		// SYNTHESIZE completing moves the engine into REVIEW — the interactive
		// Q&A stage — with the draft ready. For an unattended run that IS the
		// finish line: the report exists, and REVIEW would otherwise wait for
		// analyst input forever. Stop here with the completed report.
		if eng.Phase() == app.PhaseReview {
			return finish(eng, inv, ""), nil
		}

		switch {
		case res.Err != nil:
			return finish(eng, inv, "error"), res.Err
		case res.Done:
			return finish(eng, inv, ""), nil
		case res.Refused:
			// The provider's safety classifier declined and the engine kept its
			// place. Unattended, we can't switch models interactively, so stop
			// and return what's gathered with a clear reason.
			return finish(eng, inv, "refused: provider safety classifier declined; retry with a different --model/provider"), nil
		case res.CapReached != "":
			if opts.ExtendOnCap && !extended {
				extended = true
				eng.SetBudget(eng.Budget() * 2)
				progress(fmt.Sprintf("[sys] spend cap (%s) reached — extending budget once and continuing", res.CapReached))
				emit(eng.ContinuePastCap())
				continue
			}
			// Stop cleanly: ContinuePastCap with no further extension lets the
			// engine wrap up into synthesis rather than truncating.
			progress(fmt.Sprintf("[sys] spend cap (%s) reached — wrapping up", res.CapReached))
			emit(eng.ContinuePastCap())
			continue
		case res.AwaitQuestion != "":
			// Autonomous rarely asks, but if the model issues ask_user, answer
			// so the loop proceeds rather than blocking forever.
			eng.Provide("Proceed using your best judgment; this is an unattended run — note any assumption in the report.")
			progress("[sys] auto-answered an ask_user to keep the unattended run moving")
		case res.Checkpoint, res.TurnComplete:
			// Autonomous doesn't checkpoint, and REVIEW's TurnComplete is caught
			// by the PhaseReview check above, so this is unreachable in practice.
			// If a future mode reaches it, just continue stepping.
		}
	}
}

// RegisterInvestigateTool adds a single `investigate` tool to reg that runs a
// full BINNY investigation on the attached project and returns the report. It's
// the Phase-3 delegation entry point: one call → BINNY's whole loop.
//
// sessTemplate carries the provider/model/mode/sample already resolved by the
// command; each call clones it so one run's state never leaks into the next.
// progress is the stderr logger. Requires a provider (BYOK) — the command only
// registers this when one is configured.
func RegisterInvestigateTool(reg *tools.Registry, sessTemplate *app.Session, client *api.Client, progress func(string)) {
	reg.Add(&tools.Tool{
		Def: tools.Def("investigate",
			"Run a COMPLETE BINNY investigation on this project and return the finished report "+
				"(classification, evidence-grounded findings, IOCs, and written sections). This runs "+
				"BINNY's own triage→investigate→synthesize loop autonomously and can take several "+
				"minutes and many model rounds. Use it to delegate a whole analysis; use the "+
				"individual read/sandbox tools instead for targeted questions.",
			tools.Obj(map[string]any{
				"instructions": tools.StrProp("optional extra focus or questions to steer the investigation (e.g. 'focus on C2 and persistence', 'is CVE-X reachable?')"),
				"extend_on_cap": map[string]any{
					"type":        "boolean",
					"description": "raise the spend budget once and keep going if a cap is hit, instead of wrapping up early (default false)",
				},
			})),
		Handler: func(ctx context.Context, input json.RawMessage) (string, error) {
			var a struct {
				Instructions string `json:"instructions"`
				ExtendOnCap  bool   `json:"extend_on_cap"`
			}
			_ = json.Unmarshal(input, &a)

			// Clone the template so concurrent/sequential calls are independent,
			// and force Autonomous (no interactive checkpoints in a tool call).
			sess := *sessTemplate
			sess.Autonomy = app.Autonomous
			if g := strings.TrimSpace(a.Instructions); g != "" {
				// Fed into the triage kickoff as "Analyst intel", the existing
				// channel for steering a run. Preserve any intel already set.
				if strings.TrimSpace(sess.Intel) != "" {
					sess.Intel = sess.Intel + "\n" + g
				} else {
					sess.Intel = g
				}
			}

			res, err := RunInvestigation(ctx, &sess, client, InvestigateOptions{
				ExtendOnCap: a.ExtendOnCap,
				Progress:    progress,
			})
			if err != nil && res == nil {
				return "", err
			}
			var b strings.Builder
			if res.Stopped != "" {
				b.WriteString("> Note: run ended early (" + res.Stopped + ").\n\n")
			}
			b.WriteString(res.Report)
			b.WriteString(fmt.Sprintf("\n\n---\n_%d rounds, ~%dk tokens._\n", res.Rounds, res.Tokens/1000))
			// A provider error mid-run with a partial report: surface both.
			if err != nil {
				b.WriteString("\n_(investigation error: " + err.Error() + ")_\n")
			}
			return b.String(), nil
		},
	})
}

// finish renders the report from the investigation snapshot and records how the
// run ended.
func finish(eng *Engine, inv *Investigation, stopped string) *InvestigateResult {
	snap := inv.Snapshot()
	rounds, _ := eng.Rounds()
	return &InvestigateResult{
		Report:   renderReport(snap),
		Snapshot: snap,
		Stopped:  stopped,
		Rounds:   rounds,
		Tokens:   eng.Spent(),
	}
}

// renderReport turns the drafted sections into one Markdown document, matching
// how the TUI presents a finished draft (title per section + content). When no
// sections exist (run stopped before synthesis), it falls back to the evidence
// summary so the caller still gets the findings gathered so far.
func renderReport(snap InvestigationSnapshot) string {
	var b strings.Builder
	if len(snap.Sections) == 0 {
		b.WriteString("# Investigation incomplete\n\n")
		b.WriteString("No report sections were drafted (the run stopped before synthesis). ")
		b.WriteString("Evidence gathered so far:\n\n")
		b.WriteString(snap.EvidenceSummary())
		return b.String()
	}
	if len(snap.MalwareTypes) > 0 {
		b.WriteString(fmt.Sprintf("_Classification: %s", strings.Join(snap.MalwareTypes, ", ")))
		if snap.Confidence != "" {
			b.WriteString(" · confidence " + snap.Confidence)
		}
		b.WriteString("_\n\n")
	}
	for _, s := range snap.Sections {
		title := strings.TrimSpace(s.Title)
		if title != "" {
			b.WriteString("## " + title + "\n\n")
		}
		b.WriteString(strings.TrimSpace(s.Content) + "\n\n")
	}
	if len(snap.IOCs) > 0 {
		b.WriteString("## Indicators of Compromise\n\n")
		for _, ioc := range snap.IOCs {
			b.WriteString(fmt.Sprintf("- `%s` (%s)\n", ioc.Value, ioc.Type))
		}
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String()) + "\n"
}
