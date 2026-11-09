package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Host is the binny-side backing the gateway talks to: it supplies the profile
// list and builds a per-session engine driver. Layer 3 implements the driver;
// Layer 2 only needs profiles and session bookkeeping.
type Host interface {
	Profiles() []Profile
	// NewSessionRuntime builds the engine-backed runtime for a session on a
	// given profile. Returns an error if the profile is unknown or the engine
	// can't be built (e.g. no provider). Introduced fully in Layer 3; Layer 2
	// may return a nil runtime with no error for a lazy session.
	NewSessionRuntime(profile Profile) (Runtime, error)
}

// Runtime is the per-session engine driver (Layer 3). Declared here so the
// session model can hold one; its methods are exercised by prompt handling.
type Runtime interface {
	// Submit runs one user turn, streaming events and asking the user through io,
	// and returns when the turn reaches a terminal state.
	Submit(ctx context.Context, text string, io *TurnIO) error
	// Close releases the runtime.
	Close()
}

// EventSink streams one live event for a session (message.delta, tool.start, …).
type EventSink func(eventType string, payload any) error

// AskFunc asks the user one question mid-turn (clarify server-request) and blocks
// until they answer or the context ends. Returns the answer text; on cancel or
// error it returns ("", err) and the runtime should proceed without it.
type AskFunc func(ctx context.Context, question string, choices []string) (string, error)

// TurnIO bundles the streaming sink and the interactive prompt for one turn.
type TurnIO struct {
	Emit EventSink
	Ask  AskFunc
}

// session is one chat. runtimeID changes per activation; storedID is durable.
type session struct {
	runtimeID string
	storedID  string
	profile   Profile
	createdAt time.Time
	running   bool
	rt        Runtime
	mu        sync.Mutex

	nextRowID int64
	messages  []storedRow // canonical transcript, display chronology
}

// storedRow is one persisted transcript row (REST history shape).
type storedRow struct {
	ID        int64   `json:"id"`
	SessionID string  `json:"session_id"`
	Role      string  `json:"role"` // user | assistant
	Content   string  `json:"content"`
	Timestamp float64 `json:"timestamp"`
}

// appendRow records one transcript row and returns its physical id.
func (s *session) appendRow(role, content string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextRowID++
	id := s.nextRowID
	s.messages = append(s.messages, storedRow{
		ID: id, SessionID: s.storedID, Role: role, Content: content,
		Timestamp: float64(time.Now().Unix()),
	})
	return id
}

// history returns a shallow copy of the transcript rows.
func (s *session) history() []storedRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]storedRow, len(s.messages))
	copy(out, s.messages)
	return out
}

// gatewayHandler implements Handler for one connection. Sessions are kept on the
// shared registry so they survive a socket reconnect under the same host.
type gatewayHandler struct {
	host     Host
	sessions *sessionRegistry
	conn     *Conn

	// pending server-requests we've sent and await client replies for.
	pendingMu sync.Mutex
	pending   map[string]chan serverReply
}

type serverReply struct {
	result json.RawMessage
	err    *WireError
}

// sessionRegistry is shared across connections for one host instance.
type sessionRegistry struct {
	mu   sync.Mutex
	byID map[string]*session // keyed by storedID
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{byID: make(map[string]*session)}
}

// NewHostHandlerFactory returns a factory the gateway Server uses to build one
// Handler per socket, all sharing one session registry, plus the registry itself
// so the server can serve REST history from the same sessions.
func NewHostHandlerFactory(host Host) (func() Handler, *sessionRegistry) {
	reg := newSessionRegistry()
	factory := func() Handler {
		return &gatewayHandler{host: host, sessions: reg, pending: make(map[string]chan serverReply)}
	}
	return factory, reg
}

func (h *gatewayHandler) OnReady(ctx context.Context, c *Conn) { h.conn = c }

func (h *gatewayHandler) OnClientReply(id string, result json.RawMessage, werr *WireError) {
	h.pendingMu.Lock()
	ch, ok := h.pending[id]
	if ok {
		delete(h.pending, id)
	}
	h.pendingMu.Unlock()
	if ok {
		ch <- serverReply{result: result, err: werr}
	}
}

func (h *gatewayHandler) HandleRPC(ctx context.Context, c *Conn, method string, params json.RawMessage) (any, error) {
	h.conn = c
	switch method {
	case "gateway.ping":
		return map[string]any{"ok": true}, nil
	case "gateway.capabilities":
		return map[string]any{"per_session_exclusive_submit": true}, nil
	case "client.capabilities":
		// The client advertises server_requests support; acknowledge.
		return map[string]any{"ok": true}, nil
	case "profiles.list":
		return h.profilesList(params)
	case "session.create":
		return h.sessionCreate(params)
	case "session.resume":
		return h.sessionResume(params)
	case "session.activate":
		return h.sessionActivate(params)
	case "commands.catalog":
		return h.commandsCatalog(params)
	case "prompt.submit", "session.steer", "session.queue", "session.interrupt":
		return h.promptMethod(ctx, method, params)
	default:
		return nil, &MethodError{Code: ErrMethodNotFound, Message: "method not supported: " + method}
	}
}

func (h *gatewayHandler) profilesList(_ json.RawMessage) (any, error) {
	ps := h.host.Profiles()
	rows := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		rows = append(rows, p.wire())
	}
	return map[string]any{"profiles": rows}, nil
}

func (h *gatewayHandler) findProfile(name string) (Profile, bool) {
	for _, p := range h.host.Profiles() {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

type createParams struct {
	Profile        string `json:"profile"`
	Source         string `json:"source"`
	IdempotencyKey string `json:"idempotency_key"`
	Model          string `json:"model"`
	Provider       string `json:"provider"`
}

func (h *gatewayHandler) sessionCreate(params json.RawMessage) (any, error) {
	var p createParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &MethodError{Code: ErrInvalidParams, Message: "bad session.create params"}
	}
	prof, ok := h.findProfile(p.Profile)
	if !ok {
		return nil, &MethodError{Code: ErrNotFound, Message: "unknown profile: " + p.Profile}
	}
	s := &session{
		runtimeID: newID("rt"),
		storedID:  newID("ss"),
		profile:   prof,
		createdAt: time.Now(),
	}
	h.sessions.mu.Lock()
	h.sessions.byID[s.storedID] = s
	h.sessions.mu.Unlock()

	// A fresh session is an empty, not-yet-running draft; the runtime is built
	// lazily on first prompt (Layer 3). Create acceptance requires empty
	// messages, message_count 0, real runtime/stored IDs and an info object
	// naming the profile.
	return map[string]any{
		"session_id":        s.runtimeID,
		"stored_session_id": s.storedID,
		"session_key":       s.storedID,
		"message_count":     0,
		"messages":          []any{},
		"running":           false,
		"info": map[string]any{
			"profile_name":      prof.Name,
			"stored_session_id": s.storedID,
			"model":             defaultModelFor(prof),
			"lazy":              true,
		},
	}, nil
}

type resumeParams struct {
	SessionID string `json:"session_id"` // a STORED id
	Profile   string `json:"profile"`
}

func (h *gatewayHandler) sessionResume(params json.RawMessage) (any, error) {
	var p resumeParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &MethodError{Code: ErrInvalidParams, Message: "bad session.resume params"}
	}
	h.sessions.mu.Lock()
	s := h.sessions.byID[p.SessionID]
	h.sessions.mu.Unlock()
	if s == nil {
		return nil, &MethodError{Code: ErrNotFound, Message: "no such session: " + p.SessionID}
	}
	// Resume mints a new runtime id for the durable session.
	s.mu.Lock()
	s.runtimeID = newID("rt")
	running := s.running
	s.mu.Unlock()
	return map[string]any{
		"session_id":        s.runtimeID,
		"stored_session_id": s.storedID,
		"session_key":       s.storedID,
		"resumed":           s.storedID,
		"running":           running,
		"messages":          []any{},
		"messages_omitted":  true,
		"info": map[string]any{
			"profile_name":      s.profile.Name,
			"stored_session_id": s.storedID,
			"model":             defaultModelFor(s.profile),
		},
	}, nil
}

type activateParams struct {
	SessionID string `json:"session_id"` // a RUNTIME id
	Profile   string `json:"profile"`
}

func (h *gatewayHandler) sessionActivate(params json.RawMessage) (any, error) {
	var p activateParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &MethodError{Code: ErrInvalidParams, Message: "bad session.activate params"}
	}
	s := h.sessions.byRuntime(p.SessionID)
	if s == nil {
		return nil, &MethodError{Code: ErrNotFound, Message: "stale runtime: " + p.SessionID}
	}
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	return map[string]any{
		"session_id":        s.runtimeID,
		"stored_session_id": s.storedID,
		"session_key":       s.storedID,
		"running":           running,
		"messages":          []any{},
		"messages_omitted":  true,
		"info": map[string]any{
			"profile_name":      s.profile.Name,
			"stored_session_id": s.storedID,
			"model":             defaultModelFor(s.profile),
		},
	}, nil
}

func (h *gatewayHandler) commandsCatalog(_ json.RawMessage) (any, error) {
	// Minimal core command set; binny has no host-installed slash menu yet.
	return map[string]any{
		"pairs": [][]string{
			{"/stop", "Stop the current turn and synthesize what's gathered."},
		},
	}, nil
}

func (s *sessionRegistry) byRuntime(runtimeID string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.byID {
		sess.mu.Lock()
		rt := sess.runtimeID
		sess.mu.Unlock()
		if rt == runtimeID {
			return sess
		}
	}
	return nil
}

func defaultModelFor(p Profile) string {
	// Filled from the host's configured model in Layer 3; a placeholder keeps
	// the create/resume info object well-formed meanwhile.
	return "binny-default"
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}
