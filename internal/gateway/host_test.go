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

func (scriptedRuntime) Submit(_ context.Context, text string, io *TurnIO) error {
	_ = io.Emit("message.delta", map[string]any{"text": "analyzing "})
	_ = io.Emit("message.delta", map[string]any{"text": text})
	_ = io.Emit("message.complete", map[string]any{"text": "analyzing " + text, "status": "ok"})
	return nil
}
func (scriptedRuntime) Close() {}

// askingRuntime calls Ask once and echoes the answer, to exercise the clarify
// server-request round-trip.
type askingRuntime struct{}

func (askingRuntime) Submit(ctx context.Context, _ string, io *TurnIO) error {
	ans, err := io.Ask(ctx, "Which environment?", []string{"Test", "Production"})
	if err != nil {
		return err
	}
	_ = io.Emit("message.complete", map[string]any{"text": "using " + ans, "status": "ok"})
	return nil
}
func (askingRuntime) Close() {}

type askingHost struct{}

func (askingHost) Profiles() []Profile {
	return []Profile{{Name: "demo", Display: "Demo", IsDefault: true, Mode: app.ModeMalware, ProjectID: "p", ProjectNm: "s"}}
}
func (askingHost) NewSessionRuntime(Profile) (Runtime, error) { return askingRuntime{}, nil }

func newHostTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	factory, reg := NewHostHandlerFactory(fakeHost{})
	srv := NewServer("test", "tok-xyz", factory, reg)
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

func TestClarifyRoundTrip(t *testing.T) {
	srv := NewServer("test", "tok-xyz", func() Handler {
		return &gatewayHandler{host: askingHost{}, sessions: newSessionRegistry(), pending: make(map[string]chan serverReply)}
	}, newSessionRegistry())
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)

	c, ctx, cancel := dialWS(t, ts)
	defer cancel()
	defer c.Close(websocket.StatusNormalClosure, "")

	cr := rpc(t, ctx, c, "c1", "session.create", `{"profile":"demo","source":"bighelp","idempotency_key":"k"}`)
	var created struct{ SessionID string `json:"session_id"` }
	json.Unmarshal(cr.Result, &created)

	// Submit; the runtime will raise a clarify server-request.
	rpc(t, ctx, c, "s1", "prompt.submit", `{"session_id":"`+created.SessionID+`","profile":"demo","text":"go","queued":true}`)

	// Expect a clarify server-request; answer it.
	var clarifyID string
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && clarifyID == "" {
		in := readOne(t, ctx, c)
		if in.Kind == KindServerRequest && in.ReqMethod == "clarify" {
			clarifyID = in.ReqID
			var p struct{ Question string `json:"question"` }
			json.Unmarshal(in.ReqParams, &p)
			if p.Question != "Which environment?" {
				t.Errorf("clarify question = %q", p.Question)
			}
		}
	}
	if clarifyID == "" {
		t.Fatal("no clarify server-request arrived")
	}
	// Reply with the answer (same id, result envelope).
	writeReq(t, ctx, c, `{"jsonrpc":"2.0","id":"`+clarifyID+`","result":{"answer":"Test"}}`)

	// The runtime should complete using the answer.
	var done bool
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !done {
		in := readOne(t, ctx, c)
		if in.Kind == KindEvent && in.EventType == "message.complete" {
			var p struct{ Text string `json:"text"` }
			json.Unmarshal(in.Payload, &p)
			if p.Text != "using Test" {
				t.Errorf("complete text = %q, want 'using Test'", p.Text)
			}
			done = true
		}
	}
	if !done {
		t.Fatal("turn did not complete after clarify answer")
	}
}

func TestHistoryRESTAfterTurn(t *testing.T) {
	ts := newHostTestServer(t)
	c, ctx, cancel := dialWS(t, ts)
	defer cancel()
	defer c.Close(websocket.StatusNormalClosure, "")

	cr := rpc(t, ctx, c, "c1", "session.create", `{"profile":"demo","source":"bighelp","idempotency_key":"k"}`)
	var created struct {
		SessionID string `json:"session_id"`
		StoredID  string `json:"stored_session_id"`
	}
	json.Unmarshal(cr.Result, &created)

	rpc(t, ctx, c, "s1", "prompt.submit", `{"session_id":"`+created.SessionID+`","profile":"demo","text":"the file","queued":true}`)
	// Wait for terminal.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		in := readOne(t, ctx, c)
		if in.Kind == KindEvent && in.EventType == "session.info" {
			var p struct{ Running *bool `json:"running"` }
			json.Unmarshal(in.Payload, &p)
			if p.Running != nil && !*p.Running {
				break
			}
		}
	}

	// GET /api/sessions
	req, _ := http.NewRequest("GET", ts.URL+"/api/sessions?profile=demo", nil)
	req.Header.Set("X-Hermes-Session-Token", "tok-xyz")
	resp, _ := http.DefaultClient.Do(req)
	var sl struct {
		Sessions []struct {
			StoredID     string `json:"stored_session_id"`
			MessageCount int    `json:"message_count"`
		} `json:"sessions"`
	}
	json.NewDecoder(resp.Body).Decode(&sl)
	if len(sl.Sessions) != 1 || sl.Sessions[0].MessageCount != 2 {
		t.Fatalf("sessions list = %+v (want 1 session, 2 messages)", sl.Sessions)
	}

	// GET /api/sessions/{id}/messages
	req2, _ := http.NewRequest("GET", ts.URL+"/api/sessions/"+created.StoredID+"/messages?profile=demo&order=oldest&limit=40", nil)
	req2.Header.Set("X-Hermes-Session-Token", "tok-xyz")
	resp2, _ := http.DefaultClient.Do(req2)
	var hm struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		Pagination struct {
			Returned int `json:"returned"`
		} `json:"pagination"`
	}
	json.NewDecoder(resp2.Body).Decode(&hm)
	if len(hm.Messages) != 2 || hm.Pagination.Returned != 2 {
		t.Fatalf("messages = %+v", hm)
	}
	if hm.Messages[0].Role != "user" || hm.Messages[0].Content != "the file" {
		t.Errorf("row0 = %+v, want user 'the file'", hm.Messages[0])
	}
	if hm.Messages[1].Role != "assistant" || hm.Messages[1].Content != "analyzing the file" {
		t.Errorf("row1 = %+v, want assistant 'analyzing the file'", hm.Messages[1])
	}
}
