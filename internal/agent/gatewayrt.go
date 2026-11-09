package agent

// Engine-backed runtime for the bighelp gateway (Layer 3).
//
// The gateway gives each chat session a Runtime whose Submit runs one user turn
// and streams live events. This file is that runtime for the REAL binny engine:
// it drives the same Engine.Step loop the TUI uses and translates the engine's
// transcript Lines, token stream and lifecycle into the event vocabulary the
// bighelp app consumes (message.delta, tool.start/complete, reasoning via the
// stream sink, status.update for phases, and a terminal the gateway turns into
// session.info running:false).
//
// It is engine-shaped, not gateway-shaped: the gateway passes a plain emit
// callback (type EventEmit) so this package needs no import of internal/gateway.

import (
	"context"
	"fmt"
	"strings"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
)

// EventEmit streams one live event: an event type and a JSON-serializable
// payload. The gateway supplies this; errors are best-effort (a dropped frame
// doesn't abort the turn).
type EventEmit func(eventType string, payload any) error

// AskUser asks the person one question mid-turn and blocks for their answer. The
// gateway maps it to a clarify server-request. An empty answer or error means
// "no answer" and the engine proceeds on best judgment.
type AskUser func(ctx context.Context, question string, choices []string) (string, error)

// TurnIO is the per-turn I/O the gateway hands the runtime.
type TurnIO struct {
	Emit EventEmit
	Ask  AskUser
}

// GatewayRuntime drives one chat session's engine across turns. The engine and
// investigation persist for the life of the session, so phase progression and
// gathered evidence carry across messages, exactly as in an interactive run.
type GatewayRuntime struct {
	sess   *app.Session
	client *api.Client

	eng *Engine
	inv *Investigation
}

// NewGatewayRuntime builds a session runtime for a profile's project + mode.
// The engine is constructed up front so a provider/config error surfaces at
// session start rather than mid-turn.
func NewGatewayRuntime(sess *app.Session, client *api.Client) (*GatewayRuntime, error) {
	eng, inv, err := Build(sess, client)
	if err != nil {
		return nil, err
	}
	return &GatewayRuntime{sess: sess, client: client, eng: eng, inv: inv}, nil
}

// Model reports the engine's model id, for the session info object.
func (r *GatewayRuntime) Model() string { return r.eng.Model() }

// Submit runs one user turn to a terminal state, streaming events through emit.
// The first turn seeds the loop (triage kickoff); later turns append the user's
// message and continue. It runs the engine autonomously within the turn: no
// interactive checkpoints (the phone drives turn-by-turn, not phase-by-phase).
func (r *GatewayRuntime) Submit(ctx context.Context, text string, io *TurnIO) error {
	emit := io.Emit
	// Token-level assistant text streams as message.delta via the engine's sink.
	r.eng.SetStreamSink(func(s string) {
		_ = emit("message.delta", map[string]any{"text": s})
	})

	if !r.eng.Started() {
		// First turn: seed, then inject the user's text as the opening steer so
		// their request shapes triage.
		emitLines(emit, r.eng.Start())
		if strings.TrimSpace(text) != "" {
			r.sess.Intel = joinIntel(r.sess.Intel, text)
		}
	} else {
		r.eng.Ask(text)
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		res := r.eng.Step(ctx)
		translate(emit, res)

		switch {
		case res.Err != nil:
			return res.Err
		case res.Done:
			return nil
		case res.Refused:
			_ = emit("message.complete", map[string]any{
				"status": "error",
				"text":   "The model's safety classifier declined this turn. Try a different model/provider.",
			})
			return nil
		case res.TurnComplete:
			// REVIEW turn finished — hand control back to the phone for the next
			// message. This is the normal end of a conversational turn.
			return nil
		case res.CapReached != "":
			// Unattended within a turn: extend once, keep going, so the phone
			// isn't left with a half-finished answer.
			emitLines(emit, r.eng.ContinuePastCap())
		case res.AwaitQuestion != "":
			// The engine wants input — ask the user via a clarify server-request
			// and feed their answer straight back, so the turn continues instead
			// of stalling. If they cancel or asking isn't possible, proceed on
			// best judgment so an unattended turn still terminates.
			answer := ""
			if io.Ask != nil {
				if a, err := io.Ask(ctx, res.AwaitQuestion, nil); err == nil {
					answer = a
				}
			}
			if answer == "" {
				answer = "Proceed using your best judgment; note any assumption in the report."
			}
			r.eng.Provide(answer)
		}

		// Once synthesis hands off to REVIEW the draft is ready; end the turn.
		if r.eng.Phase() == app.PhaseReview {
			return nil
		}
	}
}

// Close releases the runtime. The engine holds no OS resources of its own; the
// toolbox's sandbox containers are per-call and already torn down.
func (r *GatewayRuntime) Close() {}

// translate maps one StepResult's transcript Lines onto live events. Streamed
// assistant prose already went out as deltas via the sink, so a "binny" line is
// only emitted when it wasn't streamed (the engine sets it that way).
func translate(emit EventEmit, res StepResult) {
	for _, ln := range res.Lines {
		t := strings.TrimSpace(ln.Text)
		if t == "" {
			continue
		}
		switch ln.Kind {
		case "binny":
			// Non-streamed assistant text (non-streaming providers / nudges).
			_ = emit("message.interim", map[string]any{"text": t})
		case "tool":
			if strings.HasPrefix(t, "→ ") {
				_ = emit("tool.complete", toolEvent(t))
			} else {
				_ = emit("tool.start", toolEvent(t))
			}
		case "err":
			_ = emit("tool.complete", map[string]any{
				"tool_id": syntheticToolID(t), "status": "error", "summary": t,
			})
		case "phase", "ok", "sys":
			_ = emit("status.update", map[string]any{"kind": "phase", "text": t})
		}
	}
}

// toolEvent builds a tool.* payload. The engine's tool lines carry a human label
// rather than a stable id, so a synthetic id groups a start with its completion
// within the turn by the label text.
func toolEvent(label string) map[string]any {
	clean := strings.TrimPrefix(label, "→ ")
	return map[string]any{
		"tool_id": syntheticToolID(clean),
		"name":    toolName(clean),
		"summary": clean,
	}
}

func toolName(label string) string {
	if i := strings.IndexAny(label, " ("); i > 0 {
		return label[:i]
	}
	return label
}

// syntheticToolID derives a short stable id from a label so start/complete pair
// up. It is a display identity only, as the contract allows.
func syntheticToolID(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return fmt.Sprintf("t%08x", h)
}

func emitLines(emit EventEmit, lines []Line) {
	translate(emit, StepResult{Lines: lines})
}

func joinIntel(existing, add string) string {
	add = strings.TrimSpace(add)
	if add == "" {
		return existing
	}
	if strings.TrimSpace(existing) == "" {
		return add
	}
	return existing + "\n" + add
}
