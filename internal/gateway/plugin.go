package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// Plugin surface (Layer 5). bighelp's optional features — cards, device tools,
// voice, workflows — are gated by GET /api/plugins/loopdy/native/context: the
// host advertises the features it implements, and the app shows only those.
//
// binny's chat runs entirely over the core transport and implements none of the
// device/voice/card features, so the honest context advertises just the baseline
// (native-context-v1, required, plus serving-profile-v1 so the profile is named)
// and marks nothing else. Absent feature = unsupported, which is exactly right:
// the app cleanly presents chat-only without claiming capabilities binny can't
// deliver. This is parity by truthful omission, not by stubbing fake features.
//
// The companion plugin's wire name is the legacy "loopdy"; paths are literal.

const pluginWireName = "loopdy"

// nativeContext is the advertised plugin context. Features binny genuinely backs
// go in Features; everything the app might look for but binny lacks is simply
// absent (optionally noted in Unavailable with a reason code).
type nativeContext struct {
	SchemaVersion   int               `json:"schemaVersion"`
	PluginVersion   string            `json:"pluginVersion"`
	RuntimeID       string            `json:"runtimeId"`
	ServingProfile  *string           `json:"servingProfileId"`
	Principal       any               `json:"principal"` // null for dashboard-session auth
	Features        []string          `json:"features"`
	Unavailable     map[string]string `json:"unavailable,omitempty"`
}

// handlePluginContext serves native/context. Only GET, no body/query. Returns
// the fixed baseline context with a strong sha256 ETag and no-store caching.
func (s *Server) handlePluginContext(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx := nativeContext{
		SchemaVersion: 1,
		PluginVersion: "binny-" + s.version,
		RuntimeID:     s.pluginRuntimeID(),
		// servingProfileId requires serving-profile-v1; binny serves a fixed
		// process profile, so name it null here (profiles are chosen per session
		// over the core transport, not by this plugin field).
		ServingProfile: nil,
		Principal:      nil, // dashboard-session auth → principal MUST be null
		Features:       []string{"native-context-v1"},
		Unavailable: map[string]string{
			// Truthfully mark the big optional families binny doesn't serve, so
			// the app shows a clear reason rather than retrying.
			"native-workflows-v1":        "unsupported_by_host",
			"native-voice-v1":            "unsupported_by_host",
			"native-device-tools-v1":     "unsupported_by_host",
			"native-cards-v1":            "unsupported_by_host",
			"native-agent-attachments-v1": "unsupported_by_host",
		},
	}
	body, _ := json.Marshal(ctx)

	sum := sha256.Sum256(body)
	etag := `"sha256:` + hex.EncodeToString(sum[:]) + `"`

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// pluginRuntimeID identifies this loaded module lifetime (stable per process).
func (s *Server) pluginRuntimeID() string {
	return "binny-gw-" + s.bootID
}
