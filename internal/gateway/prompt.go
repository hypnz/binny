package gateway

import (
	"context"
	"encoding/json"
	"fmt"
)

// askUser raises a clarify server-request to the connected client and blocks
// until the client replies ({answer:"..."}) or the context ends. The clarify
// wire shape is {session_id, question, choices?, multi_select:false}; the reply
// is {answer:string} (or {} for cancel).
func (h *gatewayHandler) askUser(ctx context.Context, runtimeID, question string, choices []string) (string, error) {
	id := newID("srv")
	ch := make(chan serverReply, 1)
	h.pendingMu.Lock()
	h.pending[id] = ch
	h.pendingMu.Unlock()
	defer func() {
		h.pendingMu.Lock()
		delete(h.pending, id)
		h.pendingMu.Unlock()
	}()

	params := map[string]any{"session_id": runtimeID, "question": question, "multi_select": false}
	if len(choices) > 0 {
		params["choices"] = choices
	}
	if err := h.conn.SendServerRequest(context.Background(), id, "clarify", params); err != nil {
		return "", err
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case rep := <-ch:
		if rep.err != nil {
			return "", fmt.Errorf("clarify declined: %s", rep.err.Message)
		}
		var r struct {
			Answer string `json:"answer"`
		}
		_ = json.Unmarshal(rep.result, &r)
		return r.Answer, nil // empty answer == cancel ({}), handled by caller
	}
}

// promptMethod handles prompt.submit / steer / queue / interrupt. Layer 3 wires
// these to a binny Engine and streams live events; until then it admits the turn
// shape so the transport is exercisable, and reports that execution is pending.
//
// This file is the seam Layer 3 replaces: the method routing and param parsing
// stay; the body gains Runtime.Submit + event streaming.
func (h *gatewayHandler) promptMethod(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "session.interrupt":
		return map[string]any{"status": "interrupted"}, nil
	case "session.steer":
		return map[string]any{"status": "queued"}, nil
	default: // prompt.submit, session.queue
		return h.submit(ctx, params)
	}
}

type submitParams struct {
	SessionID string `json:"session_id"` // runtime id
	Profile   string `json:"profile"`
	Text      string `json:"text"`
	Queued    bool   `json:"queued"`
}

func (h *gatewayHandler) submit(ctx context.Context, params json.RawMessage) (any, error) {
	var p submitParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &MethodError{Code: ErrInvalidParams, Message: "bad prompt.submit params"}
	}
	s := h.sessions.byRuntime(p.SessionID)
	if s == nil {
		// 4001 revokes the runtime until durable reattachment.
		return nil, &MethodError{Code: ErrUnauthorized, Message: "stale runtime; resume the session"}
	}
	if p.Text == "" {
		return nil, &MethodError{Code: ErrInvalidParams, Message: "empty prompt text"}
	}

	// Admit the turn (status:streaming) and run it through the Runtime. emit
	// streams live events bound to this session's runtime id; ask raises a
	// clarify server-request and blocks for the user's answer.
	emit := func(eventType string, payload any) error {
		return h.conn.Emit(context.Background(), eventType, payload, s.runtimeID, nil)
	}
	ask := func(qctx context.Context, question string, choices []string) (string, error) {
		return h.askUser(qctx, s.runtimeID, question, choices)
	}

	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()

	if rt == nil {
		built, err := h.host.NewSessionRuntime(s.profile)
		if err != nil {
			return nil, &MethodError{Code: ErrInternal, Message: "cannot start agent: " + err.Error()}
		}
		s.mu.Lock()
		s.rt = built
		rt = built
		s.mu.Unlock()
	}
	if rt == nil {
		return nil, &MethodError{Code: ErrInternal, Message: "agent runtime unavailable on this host"}
	}

	// Record the user row now (admission); capture the assistant's final text for
	// the transcript by wrapping emit.
	userRowID := s.appendRow("user", p.Text)
	var assistantText string
	recEmit := func(eventType string, payload any) error {
		switch eventType {
		case "message.delta":
			if m, ok := payload.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					assistantText += t
				}
			}
		case "message.interim":
			if m, ok := payload.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					assistantText += t
				}
			}
		case "message.complete":
			if m, ok := payload.(map[string]any); ok {
				if t, ok := m["text"].(string); ok && t != "" {
					assistantText = t // final replaces accumulated deltas
				}
			}
		}
		return emit(eventType, payload)
	}

	// Run the turn asynchronously so the admission receipt returns immediately
	// (status:streaming), then live events stream until terminal.
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
	go func() {
		_ = recEmit("message.start", map[string]any{})
		err := rt.Submit(context.Background(), p.Text, &TurnIO{Emit: recEmit, Ask: ask})
		if err != nil {
			_ = recEmit("message.complete", map[string]any{
				"status": "error", "text": err.Error(),
			})
		}
		if assistantText != "" {
			s.appendRow("assistant", assistantText)
		}
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		// running:false is the turn-end authority.
		_ = emit("session.info", map[string]any{"running": false})
	}()

	return map[string]any{"status": "streaming", "user_row_id": userRowID}, nil
}
