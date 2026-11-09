package gateway

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The conformance vectors (copied from bighelp's docs/hermes/vectors/wire.json)
// are the oracle for the frame codec: each case is one WebSocket message and the
// labels its decoder must produce. Matching them means binny's framing lines up
// with the client byte-for-byte.

type wireCase struct {
	ID       string   `json:"id"`
	Frame    string   `json:"frame"`
	Expected []string `json:"expected"`
	Purpose  string   `json:"purpose"`
}

type wireVectors struct {
	Cases []wireCase `json:"cases"`
}

// label renders one decoded Inbound as the vector's expected-label vocabulary.
func label(in Inbound) string {
	switch in.Kind {
	case KindEvent:
		return "event:" + in.EventType
	case KindResult:
		return "result:" + in.ID
	case KindFailure:
		return "failure:" + in.ID
	case KindServerRequest:
		return "request:" + in.ReqMethod
	default:
		return "?"
	}
}

func TestWireVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/wire.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v wireVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("no vectors loaded")
	}

	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got, err := DecodeMessage([]byte(c.Frame))

			// A single "reject:<reason>" expectation means the whole message
			// must be rejected with that reason.
			if len(c.Expected) == 1 && strings.HasPrefix(c.Expected[0], "reject:") {
				wantReason := strings.TrimPrefix(c.Expected[0], "reject:")
				if err == nil {
					t.Fatalf("%s: expected reject:%s, got %d messages", c.Purpose, wantReason, len(got))
				}
				var re *RejectError
				if !asReject(err, &re) {
					t.Fatalf("expected RejectError, got %T: %v", err, err)
				}
				if string(re.Reason) != wantReason {
					t.Fatalf("reject reason = %q, want %q (%s)", re.Reason, wantReason, c.Purpose)
				}
				return
			}

			// Otherwise every entry must decode and match the labels in order.
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", c.Purpose, err)
			}
			if len(got) != len(c.Expected) {
				t.Fatalf("got %d messages, want %d (%v): %s", len(got), len(c.Expected), c.Expected, c.Purpose)
			}
			for i, in := range got {
				if l := label(in); l != c.Expected[i] {
					t.Errorf("entry %d = %q, want %q (%s)", i, l, c.Expected[i], c.Purpose)
				}
			}
		})
	}
}

func asReject(err error, target **RejectError) bool {
	for err != nil {
		if re, ok := err.(*RejectError); ok {
			*target = re
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
