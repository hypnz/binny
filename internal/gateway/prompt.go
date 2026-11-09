package gateway

import (
	"context"
	"encoding/json"
)

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

	// Layer 3 builds the runtime lazily and streams the turn. For now, admit the
	// turn (status:streaming) and run it through the Runtime if the host built
	// one; otherwise report pending so the wire contract is still honored.
	emit := func(eventType string, payload any) error {
		return h.conn.Emit(ctx, eventType, payload, s.runtimeID, nil)
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

	// Run the turn asynchronously so the admission receipt returns immediately
	// (status:streaming), then live events stream until terminal.
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
	go func() {
		_ = emit("message.start", map[string]any{})
		err := rt.Submit(context.Background(), p.Text, emit)
		if err != nil {
			_ = emit("message.complete", map[string]any{
				"status": "error", "text": err.Error(),
			})
		}
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		// running:false is the turn-end authority.
		_ = emit("session.info", map[string]any{"running": false})
	}()

	return map[string]any{"status": "streaming"}, nil
}
