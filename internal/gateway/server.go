package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// Server is binny's Hermes-compatible gateway: the HTTP + WebSocket surface the
// bighelp app connects to directly. This file implements the ungated-dashboard
// auth mode (the simplest the contract allows): /api/status advertises no auth,
// GET / hands out a session token, /api/health is the authenticated readiness
// check, and /api/ws upgrades to the JSON-RPC gateway.
//
// HandlerFactory builds one Handler per accepted socket, so each connection gets
// its own owner/epoch scope.
type Server struct {
	version      string
	sessionToken string // the ungated "dashboard" token
	newHandler   func() Handler
	sessions     *sessionRegistry // shared with the handlers, for REST history
	bootID       string           // stable per-process id for plugin runtimeId
	epochCounter atomic.Uint64
}

// NewServer builds a gateway. If sessionToken is empty, a random one is minted;
// in ungated mode the token is handed to the client via GET / so a known value
// isn't required, but a stable one across restarts keeps existing clients valid.
// Pass the registry returned alongside the handler factory so REST history reads
// the same sessions the socket writes.
func NewServer(version, sessionToken string, newHandler func() Handler, sessions *sessionRegistry) *Server {
	if sessionToken == "" {
		sessionToken = randomToken()
	}
	return &Server{version: version, sessionToken: sessionToken, newHandler: newHandler, sessions: sessions, bootID: randomToken()[:16]}
}

// Token is the ungated session token this server accepts.
func (s *Server) Token() string { return s.sessionToken }

// Routes returns the gateway's HTTP handler. Mount at the server root; the
// contract's endpoints are absolute paths.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/ws", s.handleWS)
	mux.HandleFunc("/api/sessions", s.handleSessions)         // saved chat list
	mux.HandleFunc("/api/sessions/", s.handleSessionMessages) // /{id}/messages
	mux.HandleFunc("/api/plugins/"+pluginWireName+"/native/context", s.handlePluginContext)
	mux.HandleFunc("/", s.handleRoot) // ungated bootstrap page (GET /)
	return mux
}

// handleStatus is public discovery: no auth required, no token consulted.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_required": false,
		"auth_flows":    []string{}, // ungated: no sign-in flows
	})
}

// handleRoot serves the ungated bootstrap page. The client fetches GET / with
// Accept: text/html and parses exactly one inert token assignment and one
// auth-mode assignment from a <script> block. It never executes the JS.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	tok, _ := json.Marshal(s.sessionToken) // double-quoted JSON string
	page := fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>binny</title></head><body>
<script>
window.__HERMES_SESSION_TOKEN__ = %s;
window.__HERMES_AUTH_REQUIRED__ = false;
</script>
binny gateway
</body></html>`, string(tok))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

// handleHealth is the authenticated readiness check: requires the session token
// and returns {ok:true, auth_required:false}.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"auth_required": false,
		"version":       s.version,
	})
}

// handleWS authenticates and upgrades the gateway socket. Ungated auth carries
// the same token in both the ?token= query and the X-Hermes-Session-Token header.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	if !s.authedWS(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"hermes-gateway-v1"},
		// LAN/Tailscale origins vary; the token is the auth, not the Origin.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	// No read limit surprises: allow large frames (history, big tool output).
	ws.SetReadLimit(16 << 20)

	epoch := s.nextEpoch()
	c := &Conn{ws: ws, handler: s.newHandler(), replayEpoch: epoch}
	ctx := r.Context()
	serveErr := c.Serve(ctx)
	if serveErr != nil && !isNormalClose(serveErr) {
		c.Close()
	}
}

func (s *Server) authed(r *http.Request) bool {
	return r.Header.Get("X-Hermes-Session-Token") == s.sessionToken
}

func (s *Server) authedWS(r *http.Request) bool {
	if r.Header.Get("X-Hermes-Session-Token") == s.sessionToken {
		return true
	}
	return r.URL.Query().Get("token") == s.sessionToken
}

func (s *Server) nextEpoch() string {
	n := s.epochCounter.Add(1)
	return fmt.Sprintf("epoch-%d-%d", time.Now().UnixNano(), n)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "binny-" + hex.EncodeToString(b)
}

func isNormalClose(err error) bool {
	st := websocket.CloseStatus(err)
	if st == websocket.StatusNormalClosure || st == websocket.StatusGoingAway {
		return true
	}
	// context cancellation on shutdown
	return errorsIsContextDone(err)
}

func errorsIsContextDone(err error) bool {
	s := err.Error()
	return strings.Contains(s, context.Canceled.Error()) || strings.Contains(s, context.DeadlineExceeded.Error())
}
