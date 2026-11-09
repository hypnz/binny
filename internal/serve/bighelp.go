package serve

// bighelp mobile gateway control, driven from Binny Desktop's Mobile menu (and
// usable from the web UI). The gateway runs INSIDE this serve process so one
// process owns the engine and the mobile host. These routes start/stop it, report
// status, and serve a phone-facing connection page with the address, token and a
// QR code — so nothing about mobile sharing needs the CLI.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/gwhost"
)

// controller lazily builds the gateway controller from the serve process's
// config/client. Requires Options.Config to be set (Desktop/CLI pass it).
func (s *server) controller() (*gwhost.Controller, error) {
	var buildErr error
	s.bighelpOnce.Do(func() {
		if s.opts.Config == nil {
			buildErr = fmt.Errorf("mobile sharing needs binny's config; restart Binny Desktop")
			return
		}
		client, err := s.authClient()
		if err != nil {
			buildErr = err
			return
		}
		s.bighelp = gwhost.NewController(gwhost.Config{
			Endpoints: s.ep,
			Cfg:       s.opts.Config,
			Client:    client,
			Version:   s.opts.Version,
		})
	})
	if buildErr != nil {
		return nil, buildErr
	}
	return s.bighelp, nil
}

func (s *server) handleBighelpStatus(w http.ResponseWriter, r *http.Request) {
	ctrl, err := s.controller()
	if err != nil {
		writeServeJSON(w, http.StatusOK, map[string]any{"available": false, "reason": err.Error()})
		return
	}
	st := ctrl.Status()
	writeServeJSON(w, http.StatusOK, map[string]any{"available": true, "status": st})
}

// bighelpStartReq configures a sharing session. There is no project selection:
// every binny project (backend + local) is shared automatically. The caller
// chooses the analysis lens (mode), bind address and an optional fixed token.
type bighelpStartReq struct {
	Addr  string `json:"addr"`  // e.g. "0.0.0.0:8787" or ":8787"
	Token string `json:"token"` // optional fixed token
	Mode  string `json:"mode"`  // "malware" | "vuln" — default lens for every project
}

func (s *server) handleBighelpStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctrl, err := s.controller()
	if err != nil {
		writeServeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	var req bighelpStartReq
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // body optional; all fields have defaults
	}
	mode := app.ModeMalware
	if strings.EqualFold(req.Mode, "vuln") || strings.EqualFold(req.Mode, "vuln_research") {
		mode = app.ModeVuln
	}
	addr := strings.TrimSpace(req.Addr)
	if addr == "" {
		addr = "0.0.0.0:8787" // default to shareable; the page shows the real IPs
	}
	st, err := ctrl.StartAll(addr, req.Token, mode)
	if err != nil {
		writeServeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "status": st})
		return
	}
	writeServeJSON(w, http.StatusOK, map[string]any{"status": st})
}

func (s *server) handleBighelpStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctrl, err := s.controller()
	if err != nil {
		writeServeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeServeJSON(w, http.StatusOK, map[string]any{"status": ctrl.Stop()})
}

// handleBighelpConnect serves a phone-facing page with the connection address,
// token and a QR code. The Electron Mobile menu opens this in a small window.
func (s *server) handleBighelpConnect(w http.ResponseWriter, r *http.Request) {
	ctrl, err := s.controller()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	st := ctrl.Status()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !st.Running {
		fmt.Fprint(w, connectPage("Mobile sharing is off", "Start sharing from the Mobile menu, then reopen this.", "", nil, ""))
		return
	}
	primary := ""
	if len(st.ConnectURLs) > 0 {
		primary = st.ConnectURLs[0]
	}
	// QR encodes a compact "binny://connect" payload the phone (or a human) can
	// read: the base URL and token.
	payload := primary
	if st.Token != "" {
		payload = primary + "  token:" + st.Token
	}
	var qrDataURL string
	if png, err := qrcode.Encode(payload, qrcode.Medium, 320); err == nil {
		qrDataURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	fmt.Fprint(w, connectPage("Connect your phone", "In bighelp: Settings › System › Computers › Add a computer, then enter:", primary, st.ConnectURLs, qrDataURL)+tokenBlock(st.Token))
}

func tokenBlock(token string) string {
	if token == "" {
		return ""
	}
	return `<p class="k">Session token</p><pre>` + html.EscapeString(token) + `</pre></div></body></html>`
}

func connectPage(title, lead, primary string, urls []string, qr string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`</title><style>
body{font-family:-apple-system,system-ui,sans-serif;background:#0d0f14;color:#e6e9ef;margin:0;padding:28px;max-width:560px}
h1{font-size:20px;margin:0 0 6px} p{color:#aeb6c4;line-height:1.5} .k{color:#7d879b;font-size:12px;text-transform:uppercase;letter-spacing:.06em;margin:18px 0 4px}
pre{background:#161a22;border:1px solid #232a36;border-radius:8px;padding:12px;overflow:auto;color:#cdd6e4}
img{background:#fff;border-radius:12px;padding:12px;margin:14px 0}
ul{padding-left:18px} li{color:#cdd6e4;margin:3px 0}
</style></head><body><div>`)
	b.WriteString(`<h1>` + html.EscapeString(title) + `</h1>`)
	b.WriteString(`<p>` + html.EscapeString(lead) + `</p>`)
	if qr != "" {
		b.WriteString(`<img src="` + qr + `" alt="connection QR" width="320" height="320">`)
	}
	if primary != "" {
		b.WriteString(`<p class="k">Address</p><pre>` + html.EscapeString(primary) + `</pre>`)
	}
	if len(urls) > 1 {
		b.WriteString(`<p class="k">Other addresses</p><ul>`)
		for _, u := range urls[1:] {
			b.WriteString(`<li>` + html.EscapeString(u) + `</li>`)
		}
		b.WriteString(`</ul>`)
	}
	if primary == "" { // off state: close out here
		b.WriteString(`</div></body></html>`)
	}
	return b.String()
}

func writeServeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
