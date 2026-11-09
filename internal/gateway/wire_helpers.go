package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// --- JSON value inspection (presence- and type-exact, no coercion) ---

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// firstNonSpace returns the first non-whitespace byte of a JSON value, or 0.
func firstNonSpace(raw []byte) byte {
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return c
		}
	}
	return 0
}

func isJSONObject(raw []byte) bool { return firstNonSpace(raw) == '{' }

func isJSONNull(raw []byte) bool {
	return strings.TrimSpace(string(raw)) == "null"
}

// asJSONString decodes raw as a JSON string, reporting whether it was one.
func asJSONString(raw []byte) (string, bool) {
	if firstNonSpace(raw) != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func isJSONStringEq(raw []byte, want string) bool {
	s, ok := asJSONString(raw)
	return ok && s == want
}

// asJSONInt decodes raw as a JSON integer (no fraction, no exponent, finite),
// reporting whether it was one. Uses json.Number so floats are rejected.
func asJSONInt(raw []byte) (int64, bool) {
	c := firstNonSpace(raw)
	if c != '-' && (c < '0' || c > '9') {
		return 0, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var num json.Number
	if err := dec.Decode(&num); err != nil {
		return 0, false
	}
	if dec.More() {
		return 0, false
	}
	// json.Number.Int64 fails on a fractional or out-of-range value.
	n, err := num.Int64()
	if err != nil {
		return 0, false
	}
	return n, true
}

// trimRaw returns a copy of raw with surrounding whitespace removed.
func trimRaw(raw json.RawMessage) json.RawMessage {
	t := bytes.TrimSpace(raw)
	out := make(json.RawMessage, len(t))
	copy(out, t)
	return out
}

func byteLen(s string) int { return len(s) }

// depthExceeds reports whether the JSON nesting depth of raw exceeds max,
// counting only structural { and [ (not those inside strings).
func depthExceeds(raw []byte, max int) bool {
	depth, inStr, esc := 0, false, false
	for _, c := range raw {
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > max {
				return true
			}
		case '}', ']':
			depth--
		}
	}
	return false
}
