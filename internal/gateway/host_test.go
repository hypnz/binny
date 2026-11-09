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
	"openbin.ai/binny/internal/app"
)

// fakeHost is a Layer-2/3 Host with one profile and a scripted runtime that
// streams a delta + complete, so the session lifecycle and prompt streaming can
// be exercised without a real engine or provider.
type fakeHost struct{}

func (fakeHost) Profiles() []Profile {
	return []Profile{{
		Name: "demo", Display: "Demo", IsDefault: true,
		Mode: app.ModeMalware, ProjectID: "local:abc", ProjectNm: "sample.bin",
	}}
}
func (fakeHost) NewSessionRuntime(Profile) (Runtime, error) { return scriptedRuntime{}, nil }

type scriptedRuntime struct{}

func (scriptedRuntime) Submit(_ context.Context, text string, emit EventSink) error {
	_ = emit("message.delta", map[string]any{"text": "analyzing "})
	_ = emit("message.delta", map[string]any{"text": text})
	_ = emit("message.complete", map[string]any{"text": "analyzing " + text, "status": "ok"})
	return nil
}
func (scriptedRuntime) Close() {}

func newHostTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := NewServer("test", "tok-xyz", NewHostHandlerFactory(fakeHost{}))
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return ts
}

func dialWS(t *testing.T, ts *httptest.Server) (*websocket.Conn, context.Context, context.CancelFunc) {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws?token=tok-xyz"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"hermes-gateway-v1"},
		HTTPHeader:   http.Header{"X-Hermes-Session-Token": []string{"tok-xyz"}},
	})
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	// consume gateway.ready
	readOne(t, ctx, c)
	return c, ctx, cancel
}

func rpc(t *testing.T, ctx context.Context, c *websocket.Conn, id, method string, params string) Inbound {
	t.Helper()
	writeReq(t, ctx, c, `{"jsonrpc":"2.0","id":"`+id+`","method":"`+method+`","params":`+params+`}`)
	for {
		in := readOne(t, ctx, c)
		if (in.Kind == KindResult || in.Kind == KindFailure) && in.ID == id {
			return in
		}
		// skip any interleaved events
	}
}

func TestProfilesList(t *testing.T) {
	ts := newHostTestServer(t)
	c, ctx, cancel := dialWS(t, ts)
	defer cancel()
	defer c.Close(websocket.StatusNormalClosure, "")

	reply := rpc(t, ctx, c, "p1", "profiles.list", "{}")
	if reply.Kind != KindResult {
		t.Fatalf("profiles.list failed: %+v", reply)
	}
	var r struct {
		Profiles []struct {
			Name      string `json:"name"`
			IsDefault bool   `json:"is_default"`
			HasAvatar bool   `json:"has_avatar"`
		} `json:"profiles"`
	}
	json.Unmarshal(reply.Result, &r)
	if len(r.Profiles) != 1 || r.Profiles[0].Name != "demo" || !r.Profiles[0].IsDefault {
		t.Fatalf("unexpected profiles: %+v", r.Profiles)
	}
}

func TestSessionCreateThenSubmitStreams(t *testing.T) {
	ts := newHostTestServer(t)
	c, ctx, cancel := dialWS(t, ts)
	defer cancel()
	defer c.Close(websocket.StatusNormalClosure, "")

	// Create a session.
	cr := rpc(t, ctx, c, "c1", "session.create", `{"profile":"demo","source":"bighelp","idempotency_key":"k1"}`)
	if cr.Kind != KindResult {
		t.Fatalf("create failed: %+v", cr)
	}
	var created struct {
		SessionID    string `json:"session_id"`
		StoredID     string `json:"stored_session_id"`
		Running      bool   `json:"running"`
		MessageCount int    `json:"message_count"`
	}
	json.Unmarshal(cr.Result, &created)
	if created.SessionID == "" || created.StoredID == "" || created.Running || created.MessageCount != 0 {
		t.Fatalf("bad create result: %+v", created)
	}

	// Submit a prompt; expect streaming admission then live events.
	sub := rpc(t, ctx, c, "s1", "prompt.submit",
		`{"session_id":"`+created.SessionID+`","profile":"demo","text":"this binary","queued":true}`)
	if sub.Kind != KindResult {
		t.Fatalf("submit failed: %+v", sub)
	}
	var admit struct {
		Status string `json:"status"`
	}
	json.Unmarshal(sub.Result, &admit)
	if admit.Status != "streaming" {
		t.Fatalf("submit status = %q, want streaming", admit.Status)
	}

	// Collect live events until session.info running:false.
	var gotStart, gotComplete, gotRunningFalse bool
	var deltas string
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		in := readOne(t, ctx, c)
		if in.Kind != KindEvent {
			continue
		}
		switch in.EventType {
		case "message.start":
			gotStart = true
		case "message.delta":
			var p struct{ Text string `json:"text"` }
			json.Unmarshal(in.Payload, &p)
			deltas += p.Text
		case "message.complete":
			gotComplete = true
		case "session.info":
			var p struct{ Running *bool `json:"running"` }
			json.Unmarshal(in.Payload, &p)
			if p.Running != nil && !*p.Running {
				gotRunningFalse = true
			}
		}
		if gotRunningFalse {
			break
		}
	}
	if !gotStart || !gotComplete || !gotRunningFalse {
		t.Fatalf("missing lifecycle events: start=%v complete=%v running:false=%v", gotStart, gotComplete, gotRunningFalse)
	}
	if deltas != "analyzing this binary" {
		t.Errorf("accumulated deltas = %q, want 'analyzing this binary'", deltas)
	}
}
