package gateway

import "encoding/json"

// Outbound frame encoders. Every frame binny sends is one JSON object on one
// line (the reader splits on LF), UTF-8, jsonrpc "2.0".

// EncodeEvent builds an event notification: method:"event", no id, with type and
// optional payload/session_id/seq. payload, when non-nil, must marshal to an
// object. This is how binny streams message.delta, tool.start, session.info, etc.
func EncodeEvent(eventType string, payload any, sessionID string, seq *int64) ([]byte, error) {
	params := map[string]any{"type": eventType}
	if payload != nil {
		params["payload"] = payload
	}
	if sessionID != "" {
		params["session_id"] = sessionID
	}
	if seq != nil {
		params["seq"] = *seq
	}
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "event",
		"params":  params,
	})
}

// EncodeResult builds a success reply for a client request id. result may be any
// JSON value, including nil (encoded as null).
func EncodeResult(id string, result any) ([]byte, error) {
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
}

// EncodeError builds an error reply for a client request id.
func EncodeError(id string, code int, message string, data any) ([]byte, error) {
	e := map[string]any{"code": code, "message": message}
	if data != nil {
		e["data"] = data
	}
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   e,
	})
}

// EncodeServerRequest builds a server-to-client request (e.g. approval, clarify):
// a method with a string id that the client answers with a reply carrying the
// same id. id must be an opaque string the gateway tracks.
func EncodeServerRequest(id, method string, params any) ([]byte, error) {
	obj := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		obj["params"] = params
	}
	return json.Marshal(obj)
}

// JSON-RPC / gateway error codes used by the server side (from the contract's
// examples and the refusal allowlist).
const (
	ErrInvalidParams   = 4002 // mapped invalid_params
	ErrUnauthorized    = 4001
	ErrForbidden       = 4009
	ErrNotFound        = 4004
	ErrRateLimited     = 4030
	ErrMaxSessions     = 4090
	ErrSlashUseDispatch = 4018 // slash.exec → use command.dispatch
	ErrMethodNotFound  = -32601
	ErrInternal        = -32603
)
