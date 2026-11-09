package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/coder/websocket"
)

// Handler is what the gateway's higher layers implement: it answers one client
// request method and returns a result value (or a *MethodError). The conn layer
// owns framing, ordering and the reply envelope; the handler owns semantics.
//
// Emit lets a handler push events (and server-requests) to this client out of
// band — e.g. streaming message.delta during a long prompt.submit. It is safe to
// call from other goroutines; the conn serializes all writes.
type Handler interface {
	HandleRPC(ctx context.Context, c *Conn, method string, params json.RawMessage) (any, error)
	// OnReady is called once per connection, right after gateway.ready is sent,
	// so a handler can advertise initial state if needed. Optional work only.
	OnReady(ctx context.Context, c *Conn)
	// OnClientReply delivers the client's answer to a server-request this conn
	// sent earlier (matched by id). err is non-nil for an error reply.
	OnClientReply(id string, result json.RawMessage, werr *WireError)
}

// MethodError is a handler-level failure that becomes a JSON-RPC error reply.
type MethodError struct {
	Code    int
	Message string
	Data    any
}

func (e *MethodError) Error() string { return e.Message }

// Conn is one authenticated WebSocket client. One reader goroutine, one write
// mutex; frame callbacks never run concurrently (the contract requires a single
// ordered reader/writer per connection).
type Conn struct {
	ws      *websocket.Conn
	handler Handler

	writeMu sync.Mutex
	closed  bool

	// replyEpoch names this socket generation for the client's recovery logic.
	replayEpoch string
}

// Serve runs the connection: sends gateway.ready, then reads and dispatches
// frames until the socket closes or ctx is cancelled. One call per connection.
func (c *Conn) Serve(ctx context.Context) error {
	// gateway.ready is the application handshake — the client treats the socket
	// as usable only after this event, not merely after the HTTP 101.
	if err := c.emitReady(ctx); err != nil {
		return err
	}
	c.handler.OnReady(ctx, c)

	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			return err // normal close or context cancel ends the loop
		}
		msgs, derr := DecodeMessage(data)
		if derr != nil {
			// A malformed message is dropped; the contract has the client
			// validate, and a host that can't parse a client frame simply
			// ignores it rather than tearing down the socket.
			continue
		}
		for _, in := range msgs {
			c.dispatch(ctx, in)
		}
	}
}

func (c *Conn) dispatch(ctx context.Context, in Inbound) {
	switch in.Kind {
	case KindServerRequest:
		// The client is calling US (a normal client→server RPC uses a string id
		// and a method). Answer with a reply envelope.
		c.handleRequest(ctx, in.ReqID, in.ReqMethod, in.ReqParams)
	case KindResult:
		// A reply to a server-request WE sent earlier.
		c.handler.OnClientReply(in.ID, in.Result, nil)
	case KindFailure:
		c.handler.OnClientReply(in.ID, nil, in.Err)
	case KindEvent:
		// Client→server events (e.g. request.cancel) are handled by the layer
		// that tracks server-requests; route by type there if needed later.
	}
}

func (c *Conn) handleRequest(ctx context.Context, id, method string, params json.RawMessage) {
	result, err := c.handler.HandleRPC(ctx, c, method, params)
	if err != nil {
		me, ok := err.(*MethodError)
		if !ok {
			me = &MethodError{Code: ErrInternal, Message: err.Error()}
		}
		b, encErr := EncodeError(id, me.Code, me.Message, me.Data)
		if encErr == nil {
			c.writeFrame(ctx, b)
		}
		return
	}
	b, encErr := EncodeResult(id, result)
	if encErr != nil {
		b, _ = EncodeError(id, ErrInternal, "result not encodable", nil)
	}
	c.writeFrame(ctx, b)
}

// Emit sends an event to this client (streaming output). Safe for concurrent use.
func (c *Conn) Emit(ctx context.Context, eventType string, payload any, sessionID string, seq *int64) error {
	b, err := EncodeEvent(eventType, payload, sessionID, seq)
	if err != nil {
		return err
	}
	return c.writeFrame(ctx, b)
}

// SendServerRequest sends a server→client request (approval, clarify, …). The
// reply arrives via Handler.OnClientReply with the same id.
func (c *Conn) SendServerRequest(ctx context.Context, id, method string, params any) error {
	b, err := EncodeServerRequest(id, method, params)
	if err != nil {
		return err
	}
	return c.writeFrame(ctx, b)
}

func (c *Conn) emitReady(ctx context.Context) error {
	return c.Emit(ctx, "gateway.ready", map[string]any{
		"heartbeat":    true,
		"replay_epoch": c.replayEpoch,
	}, "", nil)
}

func (c *Conn) writeFrame(ctx context.Context, b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return fmt.Errorf("connection closed")
	}
	return c.ws.Write(ctx, websocket.MessageText, b)
}

// Close shuts the socket with a normal close code.
func (c *Conn) Close() {
	c.writeMu.Lock()
	c.closed = true
	c.writeMu.Unlock()
	_ = c.ws.Close(websocket.StatusNormalClosure, "")
}

// ReplayEpoch is this socket generation's recovery coordinate.
func (c *Conn) ReplayEpoch() string { return c.replayEpoch }
