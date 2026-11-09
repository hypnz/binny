package gateway

import (
	"net/http"
	"strconv"
	"strings"
)

// REST history (Layer 4): the catalog-backed transcript reads bighelp uses.
// GET /api/sessions           → saved chat list for a profile
// GET /api/sessions/{id}/messages → paged canonical transcript

// listSaved returns saved sessions for a profile (newest first).
func (r *sessionRegistry) listSaved(profile string) []*session {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*session
	for _, s := range r.byID {
		if profile == "" || s.profile.Name == profile {
			out = append(out, s)
		}
	}
	return out
}

func (r *sessionRegistry) byStored(storedID string) *session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byID[storedID]
}

func (s *Server) handleSessions(w http.ResponseWriter, req *http.Request) {
	if !s.authed(req) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	profile := req.URL.Query().Get("profile")
	sessions := s.sessions.listSaved(profile)
	rows := make([]map[string]any, 0, len(sessions))
	for _, sess := range sessions {
		sess.mu.Lock()
		rows = append(rows, map[string]any{
			"session_id":    sess.storedID,
			"stored_session_id": sess.storedID,
			"profile":       sess.profile.Name,
			"created_at":    sess.createdAt.Unix(),
			"message_count": len(sess.messages),
			"source":        "bighelp",
		})
		sess.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": rows,
		"total":    len(rows),
		"has_more": false,
	})
}

func (s *Server) handleSessionMessages(w http.ResponseWriter, req *http.Request) {
	if !s.authed(req) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	// Path: /api/sessions/{id}/messages
	rest := strings.TrimPrefix(req.URL.Path, "/api/sessions/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[1] != "messages" {
		http.NotFound(w, req)
		return
	}
	storedID := parts[0]
	sess := s.sessions.byStored(storedID)
	if sess == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such session"})
		return
	}
	q := req.URL.Query()
	if p := q.Get("profile"); p != "" && p != sess.profile.Name {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "profile mismatch"})
		return
	}
	offset := atoiDefault(q.Get("offset"), 0)
	limit := atoiDefault(q.Get("limit"), 40)
	order := q.Get("order")
	if order == "" {
		order = "latest"
	}

	all := sess.history()
	// Display chronology is oldest→newest as stored. "latest" returns the tail.
	rows := pageRows(all, offset, limit, order)

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sess.storedID,
		"profile":    sess.profile.Name,
		"messages":   rows,
		"pagination": map[string]any{
			"offset":   offset,
			"limit":    limit,
			"order":    order,
			"returned": len(rows),
		},
	})
}

// pageRows applies offset/limit over the transcript in the requested order. The
// REST rows are always returned in display chronology (oldest→newest); "latest"
// selects from the tail, "oldest" from the head.
func pageRows(all []storedRow, offset, limit int, order string) []storedRow {
	n := len(all)
	if limit <= 0 || n == 0 {
		return []storedRow{}
	}
	var window []storedRow
	if order == "oldest" {
		start := offset
		if start > n {
			start = n
		}
		end := start + limit
		if end > n {
			end = n
		}
		window = all[start:end]
	} else { // latest: offset counts back from the end
		end := n - offset
		if end < 0 {
			end = 0
		}
		start := end - limit
		if start < 0 {
			start = 0
		}
		window = all[start:end]
	}
	out := make([]storedRow, len(window))
	copy(out, window)
	return out
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
