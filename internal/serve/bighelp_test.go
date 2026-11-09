package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/config"
)

var dummyConfig = config.Config{DefaultProvider: "anthropic", DefaultModel: "claude-opus-4-8"}

// serverWithConfig builds a serve server whose bighelp controller can be created
// without real auth (newClient returns a nil-ish client; off-state paths don't
// call it).
func serverWithConfig() *server {
	return &server{
		opts:      Options{Config: &dummyConfig},
		newClient: func() (*api.Client, error) { return &api.Client{}, nil },
	}
}

// With no Config wired (older launch path), mobile sharing reports unavailable
// rather than erroring — the Desktop menu can then show it greyed with a reason.
func TestBighelpStatusUnavailableWithoutConfig(t *testing.T) {
	s := &server{opts: Options{}} // no Config
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/bighelp/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Available {
		t.Errorf("available should be false without Config")
	}
	if out.Reason == "" {
		t.Errorf("a reason should be given")
	}
}

// The connect page renders an off-state when sharing isn't running, without
// needing a backend or a started gateway.
func TestBighelpConnectOffState(t *testing.T) {
	s := serverWithConfig() // Config present, not started
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/bighelp/connect")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q, want html", ct)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	page := string(body[:n])
	if !strings.Contains(page, "Mobile sharing is off") {
		t.Errorf("off-state page missing expected copy:\n%s", page)
	}
}

func TestBighelpStopWhenNeverStarted(t *testing.T) {
	s := serverWithConfig()
	srv := httptest.NewServer(s.routes())
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/api/bighelp/stop", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("stop when idle = %d, want 200", resp.StatusCode)
	}
}
