package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"openbin.ai/binny/internal/tools"
)

// fakeReg builds a registry with two tools: one that echoes its "msg" argument,
// and one that always fails — enough to exercise success and tool-error paths.
func fakeReg() *tools.Registry {
	reg := tools.NewRegistry()
	reg.Add(&tools.Tool{
		Def: tools.Def("echo", "Echo the msg argument.",
			tools.Obj(map[string]any{"msg": tools.StrProp("text to echo")}, "msg")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct {
				Msg string `json:"msg"`
			}
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			return "echo: " + a.Msg, nil
		},
	})
	reg.Add(&tools.Tool{
		Def:     tools.Def("boom", "Always fails.", tools.Obj(map[string]any{})),
		Handler: func(context.Context, json.RawMessage) (string, error) { return "", errBoom },
	})
	return reg
}

type boomErr struct{}

func (boomErr) Error() string { return "boom" }

var errBoom = boomErr{}

// drive runs the server against a canned sequence of request lines and returns
// the decoded responses, in order. Notifications (no reply) are simply absent.
func drive(t *testing.T, reg *tools.Registry, lines ...string) []rpcResponse {
	t.Helper()
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	pr, pw := io.Pipe()
	s := NewServer(reg, "test-1.2.3")

	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), in, pw); pw.Close() }()

	var out []rpcResponse
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var resp rpcResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("bad response line %q: %v", line, err)
		}
		out = append(out, resp)
	}
	if err := <-done; err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
	return out
}

func TestInitialize(t *testing.T) {
	resps := drive(t, fakeReg(),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}`,
	)
	if len(resps) != 1 {
		t.Fatalf("want 1 response, got %d", len(resps))
	}
	b, _ := json.Marshal(resps[0].Result)
	var res initializeResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if res.ProtocolVersion != protocolVersion {
		t.Errorf("protocolVersion = %q, want %q", res.ProtocolVersion, protocolVersion)
	}
	if res.ServerInfo.Name != serverName || res.ServerInfo.Version != "test-1.2.3" {
		t.Errorf("serverInfo = %+v", res.ServerInfo)
	}
	if _, ok := res.Capabilities["tools"]; !ok {
		t.Errorf("tools capability not advertised: %+v", res.Capabilities)
	}
}

func TestInitializedNotificationHasNoReply(t *testing.T) {
	// A notification (no id) must produce no response. Pair it with a ping so
	// the loop has something to reply to and we can confirm only one reply.
	resps := drive(t, fakeReg(),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":9,"method":"ping"}`,
	)
	if len(resps) != 1 {
		t.Fatalf("want exactly 1 reply (ping only), got %d: %+v", len(resps), resps)
	}
	if string(resps[0].ID) != "9" {
		t.Errorf("reply id = %s, want 9", resps[0].ID)
	}
}

func TestToolsList(t *testing.T) {
	resps := drive(t, fakeReg(),
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	)
	b, _ := json.Marshal(resps[0].Result)
	var res listToolsResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(res.Tools))
	}
	// Registration order is preserved by the registry.
	if res.Tools[0].Name != "echo" || res.Tools[1].Name != "boom" {
		t.Errorf("tool order/names wrong: %+v", res.Tools)
	}
	if res.Tools[0].InputSchema["type"] != "object" {
		t.Errorf("echo inputSchema missing object type: %+v", res.Tools[0].InputSchema)
	}
}

func TestCallToolSuccess(t *testing.T) {
	resps := drive(t, fakeReg(),
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}`,
	)
	b, _ := json.Marshal(resps[0].Result)
	var res callToolResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Errorf("unexpected isError on success")
	}
	if len(res.Content) != 1 || res.Content[0].Text != "echo: hi" {
		t.Errorf("content = %+v, want text 'echo: hi'", res.Content)
	}
}

func TestCallToolHandlerErrorIsToolError(t *testing.T) {
	// A handler error must come back as a tool result with isError=true, not a
	// JSON-RPC error — so the host model can read it and recover.
	resps := drive(t, fakeReg(),
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"boom","arguments":{}}}`,
	)
	if resps[0].Error != nil {
		t.Fatalf("got JSON-RPC error, want tool-level error: %+v", resps[0].Error)
	}
	b, _ := json.Marshal(resps[0].Result)
	var res callToolResult
	json.Unmarshal(b, &res)
	if !res.IsError {
		t.Errorf("want isError=true for failing handler")
	}
	if !strings.Contains(res.Content[0].Text, "boom") {
		t.Errorf("error text = %q, want it to mention the failure", res.Content[0].Text)
	}
}

func TestCallUnknownToolIsToolError(t *testing.T) {
	resps := drive(t, fakeReg(),
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope","arguments":{}}}`,
	)
	if resps[0].Error != nil {
		t.Fatalf("unknown tool should be a tool-level error, got JSON-RPC error: %+v", resps[0].Error)
	}
	b, _ := json.Marshal(resps[0].Result)
	var res callToolResult
	json.Unmarshal(b, &res)
	if !res.IsError || !strings.Contains(res.Content[0].Text, "no such tool") {
		t.Errorf("want 'no such tool' error, got %+v", res)
	}
}

func TestUnknownMethodIsJSONRPCError(t *testing.T) {
	resps := drive(t, fakeReg(),
		`{"jsonrpc":"2.0","id":6,"method":"does/notexist"}`,
	)
	if resps[0].Error == nil || resps[0].Error.Code != codeMethodNotFound {
		t.Errorf("want method-not-found error, got %+v", resps[0])
	}
}

func TestParseErrorGetsReply(t *testing.T) {
	resps := drive(t, fakeReg(),
		`{this is not json`,
		`{"jsonrpc":"2.0","id":7,"method":"ping"}`,
	)
	if len(resps) != 2 {
		t.Fatalf("want 2 replies (parse error + ping), got %d", len(resps))
	}
	if resps[0].Error == nil || resps[0].Error.Code != codeParseError {
		t.Errorf("first reply should be a parse error: %+v", resps[0])
	}
}
