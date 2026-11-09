package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// echoHandler answers gateway.capabilities and gateway.ping; everything else is
// method-not-found. Enough to exercise the transport end to end.
type echoHandler struct{ ready chan struct{} }

func (h *echoHandler) HandleRPC(_ context.Context, _ *Conn, method string, _ json.RawMessage) (any, error) {
	switch method {
	case "gateway.capabilities":
		return map[string]any{"per_session_exclusive_submit": true}, nil
	case "gateway.ping":
		return map[string]any{"ok": true}, nil
	default:
		return nil, &MethodError{Code: ErrMethodNotFound, Message: "method not found: " + method}
	}
}
func (h *echoHandler) OnReady(context.Context, *Conn) {
	if h.ready != nil {
		close(h.ready)
	}
}
func (h *echoHandler) OnClientReply(string, json.RawMessage, *WireError) {}

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	srv := NewServer("test", "tok-123", func() Handler { return &echoHandler{} })
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return srv, ts
}

func TestStatusIsUngated(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st struct {
		AuthRequired bool     `json:"auth_required"`
		AuthFlows    []string `json:"auth_flows"`
	}
	json.NewDecoder(resp.Body).Decode(&st)
	if st.AuthRequired {
		t.Errorf("auth_required should be false in ungated mode")
	}
}

func TestBootstrapPageCarriesToken(t *testing.T) {
	srv, ts := newTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	page := string(body[:n])
	if !strings.Contains(page, `window.__HERMES_SESSION_TOKEN__ = "`+srv.Token()+`"`) {
		t.Errorf("bootstrap page missing token assignment:\n%s", page)
	}
	if !strings.Contains(page, `window.__HERMES_AUTH_REQUIRED__ = false`) {
		t.Errorf("bootstrap page missing auth-mode assignment")
	}
}

func TestHealthRequiresToken(t *testing.T) {
	_, ts := newTestServer(t)
	// No token → 401.
	resp, _ := http.Get(ts.URL + "/api/health")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("health without token = %d, want 401", resp.StatusCode)
	}
	// With token → ok.
	req, _ := http.NewRequest("GET", ts.URL+"/api/health", nil)
	req.Header.Set("X-Hermes-Session-Token", "tok-123")
	resp2, _ := http.DefaultClient.Do(req)
	var h struct {
		OK bool `json:"ok"`
	}
	json.NewDecoder(resp2.Body).Decode(&h)
	if !h.OK {
		t.Errorf("health with token should be ok")
	}
}

func TestWebSocketHandshakeAndRPC(t *testing.T) {
	_, ts := newTestServer(t)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws?token=tok-123"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols:    []string{"hermes-gateway-v1"},
		HTTPHeader:      http.Header{"X-Hermes-Session-Token": []string{"tok-123"}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	// First frame must be gateway.ready.
	in := readOne(t, ctx, c)
	if in.Kind != KindEvent || in.EventType != "gateway.ready" {
		t.Fatalf("first frame = %+v, want gateway.ready event", in)
	}

	// Ask for capabilities; expect per_session_exclusive_submit:true.
	writeReq(t, ctx, c, `{"jsonrpc":"2.0","id":"cap-1","method":"gateway.capabilities","params":{}}`)
	reply := readOne(t, ctx, c)
	if reply.Kind != KindResult || reply.ID != "cap-1" {
		t.Fatalf("capabilities reply = %+v", reply)
	}
	var caps struct {
		Excl bool `json:"per_session_exclusive_submit"`
	}
	json.Unmarshal(reply.Result, &caps)
	if !caps.Excl {
		t.Errorf("per_session_exclusive_submit should be true")
	}

	// Unknown method → error reply.
	writeReq(t, ctx, c, `{"jsonrpc":"2.0","id":"x-1","method":"does.notexist","params":{}}`)
	e := readOne(t, ctx, c)
	if e.Kind != KindFailure || e.ID != "x-1" || e.Err.Code != ErrMethodNotFound {
		t.Fatalf("unknown-method reply = %+v", e)
	}
}

func readOne(t *testing.T, ctx context.Context, c *websocket.Conn) Inbound {
	t.Helper()
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	msgs, err := DecodeMessage(data)
	if err != nil || len(msgs) == 0 {
		t.Fatalf("decode %q: %v", data, err)
	}
	return msgs[0]
}

func writeReq(t *testing.T, ctx context.Context, c *websocket.Conn, frame string) {
	t.Helper()
	if err := c.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
		t.Fatalf("write: %v", err)
	}
}
