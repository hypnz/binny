// Package gateway implements the server side of the Hermes native transport
// contract — the wire protocol the bighelp app speaks — so binny can be a host
// bighelp connects to directly, with no Hermes in between.
//
// This file is the wire codec: it turns one received WebSocket text frame into a
// classified inbound message, and encodes outbound events and replies. It is the
// bedrock the rest of the gateway sits on, and it is verified against bighelp's
// own conformance vectors (testdata/wire.json) so binny's framing matches the
// client's decoder exactly.
//
// Framing rules (from docs/hermes CONNECTION §8):
//   - UTF-8 JSON text; one WebSocket message MAY carry several newline-delimited
//     JSON objects (NDJSON), processed in order. Not JSON-RPC array batches.
//   - A reply has a string id and exactly one of result|error, never params or
//     method, never a non-string id.
//   - An event is method:"event", no id, object params, with a nonempty string
//     params.type (≤256 bytes) and, if present, object (non-null) payload.
//   - Any other non-event method WITH a string id is a server-to-client request.
//   - Everything malformed is rejected; the whole NDJSON message is validated
//     before any entry is delivered (atomic).
package gateway

import (
	"encoding/json"
	"unicode/utf8"
)

// Bounds from the contract.
const (
	maxServerRequestIDBytes = 1024
	maxEventTypeBytes       = 256
	maxCancelReasonBytes    = 4096
	maxJSONNestingDepth     = 64 // "nesting-too-deep" → messageTooLarge
)

// RejectReason classifies why a frame was rejected, matching the vector labels.
type RejectReason string

const (
	RejectInvalidResponse RejectReason = "invalidResponse"
	RejectMessageTooLarge RejectReason = "messageTooLarge"
)

// RejectError carries a reject reason for a malformed frame.
type RejectError struct{ Reason RejectReason }

func (e *RejectError) Error() string { return "frame rejected: " + string(e.Reason) }

func reject(r RejectReason) error { return &RejectError{Reason: r} }

// MsgKind is the classification of one inbound frame.
type MsgKind int

const (
	KindEvent         MsgKind = iota // method:"event"
	KindResult                       // reply with result
	KindFailure                      // reply with error
	KindServerRequest                // non-event method + string id (server→client)
)

// Inbound is one decoded, validated frame.
type Inbound struct {
	Kind MsgKind

	// Reply (KindResult / KindFailure): the correlating id.
	ID string
	// KindResult: the raw result value (any JSON, including null).
	Result json.RawMessage
	// KindFailure: the error object.
	Err *WireError

	// Event (KindEvent): type + optional payload + optional session/seq.
	EventType string
	Payload   json.RawMessage // object or absent (never null)
	SessionID string          // optional
	Seq       *int64          // optional integer

	// ServerRequest (KindServerRequest): opaque id + method + params.
	ReqID     string
	ReqMethod string
	ReqParams json.RawMessage // object; absent/null normalized to {}
}

// WireError is a JSON-RPC error object.
type WireError struct {
	Code    int             `json:"code"`
	Message string          `json:"message,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// DecodeMessage splits one WebSocket message into NDJSON lines and decodes each,
// validating the WHOLE message before returning any entry (atomic): if any line
// is malformed, nothing is delivered. Blank/space/tab/CR-only lines are skipped;
// at least one object is required.
func DecodeMessage(msg []byte) ([]Inbound, error) {
	if !utf8.Valid(msg) {
		return nil, reject(RejectInvalidResponse)
	}
	lines := splitNDJSON(msg)
	if len(lines) == 0 {
		return nil, reject(RejectInvalidResponse)
	}
	out := make([]Inbound, 0, len(lines))
	for _, ln := range lines {
		in, err := decodeFrame(ln)
		if err != nil {
			return nil, err // atomic: reject the whole message
		}
		out = append(out, in)
	}
	return out, nil
}

// splitNDJSON splits on LF and drops lines that are empty or only spaces/tabs/CR.
// Literal newlines cannot occur inside JSON strings, so a line split is safe.
func splitNDJSON(msg []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i <= len(msg); i++ {
		if i == len(msg) || msg[i] == '\n' {
			line := msg[start:i]
			if !blank(line) {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	return lines
}

func blank(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' {
			return false
		}
	}
	return true
}

// rawEnvelope captures the top-level fields by PRESENCE. A map is used because a
// struct of *json.RawMessage cannot tell "key: null" from "key absent" (Go sets
// the pointer to nil in both cases), and that distinction is load-bearing here:
// result:null is a valid reply, payload:null is an invalid event.
type rawEnvelope struct {
	jsonrpc     json.RawMessage
	id          json.RawMessage
	method      json.RawMessage
	params      json.RawMessage
	result      json.RawMessage
	err         json.RawMessage
	hasID       bool
	hasMethod   bool
	hasParams   bool
	hasResult   bool
	hasError    bool
	hasJSONRPC  bool
	extraTop    bool // an unknown top-level key was present
}

func parseEnvelope(line []byte) (rawEnvelope, bool) {
	var m map[string]json.RawMessage
	dec := json.NewDecoder(bytesReader(line))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return rawEnvelope{}, false
	}
	if dec.More() {
		return rawEnvelope{}, false
	}
	var env rawEnvelope
	for k, v := range m {
		switch k {
		case "jsonrpc":
			env.jsonrpc, env.hasJSONRPC = v, true
		case "id":
			env.id, env.hasID = v, true
		case "method":
			env.method, env.hasMethod = v, true
		case "params":
			env.params, env.hasParams = v, true
		case "result":
			env.result, env.hasResult = v, true
		case "error":
			env.err, env.hasError = v, true
		default:
			env.extraTop = true
		}
	}
	return env, true
}

func decodeFrame(line []byte) (Inbound, error) {
	if depthExceeds(line, maxJSONNestingDepth) {
		return Inbound{}, reject(RejectMessageTooLarge)
	}
	if !isJSONObject(line) {
		return Inbound{}, reject(RejectInvalidResponse)
	}
	env, ok := parseEnvelope(line)
	if !ok {
		return Inbound{}, reject(RejectInvalidResponse)
	}
	// jsonrpc must be exactly "2.0".
	if !env.hasJSONRPC || !isJSONStringEq(env.jsonrpc, "2.0") {
		return Inbound{}, reject(RejectInvalidResponse)
	}

	switch {
	case !env.hasMethod && (env.hasResult || env.hasError):
		return decodeReply(env)
	case env.hasMethod:
		return decodeMethodFrame(env)
	default:
		return Inbound{}, reject(RejectInvalidResponse)
	}
}

// decodeReply handles result/error envelopes (no method).
func decodeReply(env rawEnvelope) (Inbound, error) {
	// id must be present and a string, bounded in length.
	if !env.hasID {
		return Inbound{}, reject(RejectInvalidResponse)
	}
	id, ok := asJSONString(env.id)
	if !ok {
		return Inbound{}, reject(RejectInvalidResponse)
	}
	if byteLen(id) > maxServerRequestIDBytes { // id-too-long
		return Inbound{}, reject(RejectInvalidResponse)
	}
	// Never params; exactly one of result|error.
	if env.hasParams {
		return Inbound{}, reject(RejectInvalidResponse)
	}
	if env.hasResult == env.hasError { // both or neither
		return Inbound{}, reject(RejectInvalidResponse)
	}
	if env.hasResult {
		return Inbound{Kind: KindResult, ID: id, Result: trimRaw(env.result)}, nil
	}
	we, err := decodeWireError(env.err)
	if err != nil {
		return Inbound{}, err
	}
	return Inbound{Kind: KindFailure, ID: id, Err: we}, nil
}

// decodeMethodFrame handles events (method:"event") and server requests
// (any other method + string id).
func decodeMethodFrame(env rawEnvelope) (Inbound, error) {
	if env.hasResult || env.hasError {
		return Inbound{}, reject(RejectInvalidResponse) // request/event can't carry result/error
	}
	method, ok := asJSONString(env.method)
	if !ok {
		return Inbound{}, reject(RejectInvalidResponse) // method must be a string
	}
	if method == "event" {
		return decodeEvent(env)
	}
	// Server-to-client request.
	if !validMethodName(method) {
		return Inbound{}, reject(RejectInvalidResponse) // empty / space / non-ASCII / too long
	}
	if !env.hasID {
		return Inbound{}, reject(RejectInvalidResponse)
	}
	id, ok := asJSONString(env.id)
	if !ok {
		return Inbound{}, reject(RejectInvalidResponse)
	}
	if byteLen(id) > maxServerRequestIDBytes { // id-too-long
		return Inbound{}, reject(RejectInvalidResponse)
	}
	// params may be object, absent or null; absent/null → {}.
	params := json.RawMessage("{}")
	if env.hasParams && !isJSONNull(env.params) {
		if !isJSONObject(env.params) {
			return Inbound{}, reject(RejectInvalidResponse) // request-array-params
		}
		params = trimRaw(env.params)
	}
	return Inbound{Kind: KindServerRequest, ReqID: id, ReqMethod: method, ReqParams: params}, nil
}

// validMethodName enforces the method token rules: nonempty, ≤256 bytes, and
// printable ASCII without spaces (the vectors reject "has space" and "méthod").
func validMethodName(m string) bool {
	if m == "" || byteLen(m) > maxEventTypeBytes {
		return false
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if c <= 0x20 || c >= 0x7f { // control, space, or non-ASCII byte
			return false
		}
	}
	return true
}

// decodeEvent validates an event envelope: no id, object params, nonempty string
// type ≤256 bytes, optional object (non-null) payload, optional string
// session_id, optional integer seq. request.cancel has an exact payload shape.
func decodeEvent(env rawEnvelope) (Inbound, error) {
	if env.hasID {
		return Inbound{}, reject(RejectInvalidResponse) // event-with-id
	}
	if !env.hasParams || !isJSONObject(env.params) {
		return Inbound{}, reject(RejectInvalidResponse)
	}
	var p map[string]json.RawMessage
	if err := json.Unmarshal(env.params, &p); err != nil {
		return Inbound{}, reject(RejectInvalidResponse)
	}
	typeRaw, hasType := p["type"]
	if !hasType {
		return Inbound{}, reject(RejectInvalidResponse) // event-missing-type
	}
	etype, ok := asJSONString(typeRaw)
	if !ok || etype == "" || byteLen(etype) > maxEventTypeBytes {
		return Inbound{}, reject(RejectInvalidResponse) // empty-type / non-string
	}
	in := Inbound{Kind: KindEvent, EventType: etype}

	if payRaw, has := p["payload"]; has {
		if isJSONNull(payRaw) || !isJSONObject(payRaw) {
			return Inbound{}, reject(RejectInvalidResponse) // null/array payload
		}
		in.Payload = trimRaw(payRaw)
	}
	if sidRaw, has := p["session_id"]; has && !isJSONNull(sidRaw) {
		sid, ok := asJSONString(sidRaw)
		if !ok {
			return Inbound{}, reject(RejectInvalidResponse) // number-session
		}
		in.SessionID = sid
	}
	if seqRaw, has := p["seq"]; has && !isJSONNull(seqRaw) {
		n, ok := asJSONInt(seqRaw)
		if !ok {
			return Inbound{}, reject(RejectInvalidResponse) // string/fractional seq
		}
		in.Seq = &n
	}

	// request.cancel carries an exact payload shape: {id, method, reason}.
	if etype == "request.cancel" {
		if err := validateCancelPayload(in.Payload); err != nil {
			return Inbound{}, err
		}
	}
	return in, nil
}

func validateCancelPayload(payload json.RawMessage) error {
	if len(payload) == 0 {
		return reject(RejectInvalidResponse)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return reject(RejectInvalidResponse)
	}
	if len(raw) != 3 { // exactly id, method, reason — no extra keys
		return reject(RejectInvalidResponse)
	}
	idRaw, ok1 := raw["id"]
	mRaw, ok2 := raw["method"]
	rRaw, ok3 := raw["reason"]
	if !ok1 || !ok2 || !ok3 {
		return reject(RejectInvalidResponse)
	}
	id, ok := asJSONString(idRaw)
	if !ok || id == "" {
		return reject(RejectInvalidResponse)
	}
	m, ok := asJSONString(mRaw)
	if !ok || m == "" {
		return reject(RejectInvalidResponse)
	}
	reason, ok := asJSONString(rRaw)
	if !ok || byteLen(reason) > maxCancelReasonBytes {
		return reject(RejectInvalidResponse)
	}
	return nil
}

func decodeWireError(raw json.RawMessage) (*WireError, error) {
	if !isJSONObject(raw) {
		return nil, reject(RejectInvalidResponse)
	}
	var probe struct {
		Code    *json.RawMessage `json:"code"`
		Message *json.RawMessage `json:"message"`
		Data    json.RawMessage  `json:"data"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, reject(RejectInvalidResponse)
	}
	if probe.Code == nil {
		return nil, reject(RejectInvalidResponse)
	}
	code, ok := asJSONInt(*probe.Code)
	if !ok { // error-code-string vector: code must be an integer
		return nil, reject(RejectInvalidResponse)
	}
	we := &WireError{Code: int(code), Data: probe.Data}
	if probe.Message != nil {
		if m, ok := asJSONString(*probe.Message); ok {
			we.Message = m
		}
	}
	return we, nil
}
