// Package mcp serves BINNY's tool registry over the Model Context Protocol
// (MCP) stdio transport, so a host that speaks MCP — a Hermes computer, Claude
// Desktop, or any other MCP client — can drive BINNY's reverse-engineering
// tools as its own.
//
// This is a thin, dependency-free bridge, not a second agent. It exposes the
// SAME *tools.Registry the TUI and Desktop build (list_functions, get_function,
// get_strings, get_imports, xrefs, reachability, decompiled-source reads, and
// so on). The HOST's model becomes the analyst; BINNY supplies the tools and
// the project it reads from. BINNY's own investigate/report loop
// (internal/agent) is deliberately out of scope here — see docs on the
// agent-service path for that.
//
// Transport: newline-delimited JSON-RPC 2.0 over stdin/stdout, as the MCP
// stdio transport specifies. One JSON object per line, no embedded newlines;
// logs go to stderr so they never corrupt the stream. The implementation is
// synchronous (one request handled at a time), which is all a tool server
// needs and keeps ordering trivial.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"openbin.ai/binny/internal/tools"
)

// protocolVersion is the MCP revision this server implements. Clients send
// their own in `initialize`; MCP's rule is that the server echoes a version it
// supports, so we return ours and let the client decide to proceed.
const protocolVersion = "2024-11-05"

// serverName / serverVersion identify this server in the initialize result.
const serverName = "binny"

// Server bridges a tools.Registry to the MCP stdio transport.
type Server struct {
	reg     *tools.Registry
	version string // binny version, surfaced in serverInfo

	mu  sync.Mutex // serialises writes to out
	out *bufio.Writer

	// Logf receives human-readable diagnostics (never JSON-RPC). Defaults to
	// discarding; the subcommand points it at stderr.
	Logf func(format string, args ...any)
}

// NewServer builds an MCP server over the given registry. `version` is BINNY's
// version string for serverInfo.
func NewServer(reg *tools.Registry, version string) *Server {
	return &Server{reg: reg, version: version, Logf: func(string, ...any) {}}
}

// ---- JSON-RPC 2.0 envelopes ------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent => notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// JSON-RPC 2.0 standard error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// ---- MCP payloads ----------------------------------------------------------

type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      serverInfo     `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpTool is one entry in tools/list. inputSchema is a JSON Schema object —
// exactly what llm.Tool.InputSchema already holds.
type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type listToolsResult struct {
	Tools []mcpTool `json:"tools"`
}

type callToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// contentBlock is a piece of tool output. BINNY tools return plain text.
type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// callToolResult carries the tool's output. isError=true reports a tool-level
// failure (bad argument, backend error) WITHOUT failing the JSON-RPC call, so
// the host's model can read the message and recover — the same contract
// tools.Registry.Run uses internally.
type callToolResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ---- Serve loop ------------------------------------------------------------

// Serve reads newline-delimited JSON-RPC from r and writes responses to w until
// r reaches EOF or ctx is cancelled. It returns nil on a clean EOF (the client
// closed stdin), which is the normal way an MCP stdio session ends.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	s.out = bufio.NewWriter(w)
	sc := bufio.NewScanner(r)
	// Decompiled functions and source reads can be large; give the line
	// scanner room well beyond the default 64 KiB so a fat request is never
	// silently truncated into a parse error.
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)

	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Bytes()
		if len(trimSpace(line)) == 0 {
			continue
		}
		s.handleLine(ctx, line)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	return nil
}

// handleLine decodes one request line and dispatches it. Parse failures and
// malformed envelopes get a best-effort error reply (null id) per JSON-RPC.
func (s *Server) handleLine(ctx context.Context, line []byte) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		s.Logf("parse error: %v", err)
		s.writeError(nil, codeParseError, "parse error", err.Error())
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		s.writeError(req.ID, codeInvalidRequest, "invalid request", nil)
		return
	}

	// A request with no id is a notification: act on it, never reply.
	isNotification := len(req.ID) == 0

	switch req.Method {
	case "initialize":
		s.reply(req.ID, s.handleInitialize())
	case "notifications/initialized", "initialized":
		// Client finished the handshake. Nothing to do; never reply.
	case "ping":
		s.reply(req.ID, map[string]any{})
	case "tools/list":
		s.reply(req.ID, listToolsResult{Tools: s.toolList()})
	case "tools/call":
		s.handleCallTool(ctx, req)
	default:
		if !isNotification {
			s.writeError(req.ID, codeMethodNotFound, "method not found: "+req.Method, nil)
		} else {
			s.Logf("ignoring unknown notification %q", req.Method)
		}
	}
}

func (s *Server) handleInitialize() initializeResult {
	return initializeResult{
		ProtocolVersion: protocolVersion,
		Capabilities: map[string]any{
			// We serve tools; the list is fixed for the session, so no
			// listChanged subscription is advertised.
			"tools": map[string]any{},
		},
		ServerInfo: serverInfo{Name: serverName, Version: s.version},
		Instructions: "BINNY reverse-engineering tools for the project this server was " +
			"started on. Call get_metadata first to orient, then read functions, " +
			"strings, imports and cross-references. Each tool result is a summary to " +
			"act on; narrow with arguments rather than dumping everything.",
	}
}

// toolList projects the registry's definitions into MCP tool entries. An empty
// or missing input schema becomes an empty-object schema, which MCP requires.
func (s *Server) toolList() []mcpTool {
	defs := s.reg.Defs()
	out := make([]mcpTool, 0, len(defs))
	for _, d := range defs {
		schema := d.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, mcpTool{
			Name:        d.Name,
			Description: d.Description,
			InputSchema: schema,
		})
	}
	return out
}

func (s *Server) handleCallTool(ctx context.Context, req rpcRequest) {
	var p callToolParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.writeError(req.ID, codeInvalidParams, "invalid tools/call params", err.Error())
		return
	}
	if p.Name == "" {
		s.writeError(req.ID, codeInvalidParams, "tools/call requires a tool name", nil)
		return
	}
	if !s.reg.Has(p.Name) {
		// Unknown tool is a tool-level error (so the model can list and retry),
		// not a transport error.
		s.reply(req.ID, callToolResult{
			Content: []contentBlock{{Type: "text", Text: "no such tool: " + p.Name}},
			IsError: true,
		})
		return
	}
	// Arguments default to an empty object when omitted, matching the handlers'
	// expectation of a JSON object.
	args := p.Arguments
	if len(trimSpace(args)) == 0 {
		args = json.RawMessage("{}")
	}
	s.Logf("tools/call %s", p.Name)
	out, isErr := s.reg.Run(ctx, p.Name, args)
	s.reply(req.ID, callToolResult{
		Content: []contentBlock{{Type: "text", Text: out}},
		IsError: isErr,
	})
}

// ---- writers ---------------------------------------------------------------

func (s *Server) reply(id json.RawMessage, result any) {
	s.writeMessage(rpcResponse{JSONRPC: "2.0", ID: idOrNull(id), Result: result})
}

func (s *Server) writeError(id json.RawMessage, code int, msg string, data any) {
	s.writeMessage(rpcResponse{
		JSONRPC: "2.0",
		ID:      idOrNull(id),
		Error:   &rpcError{Code: code, Message: msg, Data: data},
	})
}

// writeMessage serialises one response as a single line. Writes are serialised
// by mu so concurrent callers (there are none today, but keep it safe) never
// interleave bytes on the wire.
func (s *Server) writeMessage(msg rpcResponse) {
	b, err := json.Marshal(msg)
	if err != nil {
		s.Logf("marshal response: %v", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Write(b)
	s.out.WriteByte('\n')
	if err := s.out.Flush(); err != nil {
		s.Logf("flush: %v", err)
	}
}

// idOrNull returns a JSON null id when the request carried none, so every
// response is a well-formed JSON-RPC object.
func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

// trimSpace trims ASCII whitespace without pulling in bytes/strings for a
// hot-path check.
func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && isSpace(b[i]) {
		i++
	}
	for j > i && isSpace(b[j-1]) {
		j--
	}
	return b[i:j]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
