// Package gwhost builds and runs the bighelp gateway as a controllable service,
// shared by the `binny bighelp` CLI subcommand and by Binny Desktop (which drives
// it from menus over /api/bighelp/* instead of the CLI).
//
// It owns three things: resolving a project reference into an api.Project,
// implementing gateway.Host (profile → engine-backed runtime), and a Controller
// that starts/stops the HTTP+WebSocket gateway on a listener and reports status.
package gwhost

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/gateway"
	"openbin.ai/binny/internal/store"
)

// ProfileSpec selects one project to serve as a bighelp profile. Still used by
// the CLI for an explicit --project; Desktop auto-enumerates instead.
type ProfileSpec struct {
	ProjectRef string   // backend id, local:<sha>, or a local sha
	Mode       app.Mode // MALWARE | VULN_RESEARCH
	Sample     string   // optional raw sample path (enables sandbox/decompile)
}

// Config is everything the host needs to build runtimes.
type Config struct {
	Endpoints config.Endpoints
	Cfg       *config.Config
	Client    *api.Client
	Version   string
}

// AllProjectSpecs enumerates every project binny knows — the account's backend
// projects (if signed in) and every local decompile on disk — as specs in the
// given mode. This is how Desktop shares "all projects" without the user picking.
// Backend-list failures (offline / not signed in) are non-fatal: local projects
// still come through.
func AllProjectSpecs(client *api.Client, mode app.Mode) []ProfileSpec {
	var specs []ProfileSpec
	seen := map[string]bool{}

	// Local decompiles first (always available, no network).
	for _, m := range store.List() {
		id := store.LocalID(m.Sha256)
		if seen[id] {
			continue
		}
		seen[id] = true
		specs = append(specs, ProfileSpec{ProjectRef: id, Mode: mode})
	}
	// Backend projects, best-effort.
	if client != nil {
		if projects, err := client.ListProjects(); err == nil {
			for _, p := range projects {
				if seen[p.ID] {
					continue
				}
				seen[p.ID] = true
				specs = append(specs, ProfileSpec{ProjectRef: p.ID, Mode: mode})
			}
		}
	}
	return specs
}

// Host implements gateway.Host: it maps each profile to a binny project+mode and
// builds an engine-backed runtime per session.
type Host struct {
	cfg      Config
	profiles []gateway.Profile
	samples  map[string]string // profile name → sample path
}

// BuildHost resolves the given specs into profiles and returns a ready Host.
func BuildHost(cfg Config, specs []ProfileSpec) (*Host, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("no projects selected")
	}
	h := &Host{cfg: cfg, samples: map[string]string{}}
	for i, sp := range specs {
		proj, err := ResolveProject(cfg.Client, sp.ProjectRef)
		if err != nil {
			return nil, err
		}
		name := profileName(proj.Name, i)
		h.profiles = append(h.profiles, gateway.Profile{
			Name:      name,
			Display:   proj.Name,
			IsDefault: i == 0,
			Mode:      sp.Mode,
			ProjectID: proj.ID,
			ProjectNm: proj.Name,
		})
		h.samples[name] = strings.TrimSpace(sp.Sample)
	}
	return h, nil
}

// Profiles implements gateway.Host.
func (h *Host) Profiles() []gateway.Profile { return h.profiles }

// NewSessionRuntime implements gateway.Host.
func (h *Host) NewSessionRuntime(profile gateway.Profile) (gateway.Runtime, error) {
	proj, err := ResolveProject(h.cfg.Client, profile.ProjectID)
	if err != nil {
		return nil, err
	}
	prov := h.cfg.Cfg.Find(h.cfg.Cfg.DefaultProvider)
	if prov == nil && len(h.cfg.Cfg.Providers) > 0 {
		prov = &h.cfg.Cfg.Providers[0]
	}
	if prov == nil {
		return nil, fmt.Errorf("no LLM provider configured (run 'binny' once to set one up)")
	}
	sess := &app.Session{
		Endpoints:  h.cfg.Endpoints,
		Config:     h.cfg.Cfg,
		API:        h.cfg.Client,
		Project:    proj,
		Mode:       profile.Mode,
		Autonomy:   app.Autonomous,
		Provider:   prov,
		Model:      h.cfg.Cfg.DefaultModel,
		SamplePath: h.samples[profile.Name],
	}
	rt, err := agent.NewGatewayRuntime(sess, h.cfg.Client)
	if err != nil {
		return nil, err
	}
	return &runtimeAdapter{rt: rt}, nil
}

// runtimeAdapter bridges agent.GatewayRuntime to gateway.Runtime.
type runtimeAdapter struct{ rt *agent.GatewayRuntime }

func (a *runtimeAdapter) Submit(ctx context.Context, text string, io *gateway.TurnIO) error {
	return a.rt.Submit(ctx, text, &agent.TurnIO{
		Emit: func(t string, p any) error { return io.Emit(t, p) },
		Ask:  func(c context.Context, q string, ch []string) (string, error) { return io.Ask(c, q, ch) },
	})
}
func (a *runtimeAdapter) Close() { a.rt.Close() }

// Controller runs the gateway as a start/stoppable service, for Desktop.
type Controller struct {
	cfg Config

	mu      sync.Mutex
	running bool
	addr    string
	token   string
	profs   []gateway.Profile
	httpSrv *http.Server
	ln      net.Listener
}

// NewController builds a stopped controller.
func NewController(cfg Config) *Controller { return &Controller{cfg: cfg} }

// Status is a snapshot of the controller for the UI.
type Status struct {
	Running  bool             `json:"running"`
	Addr     string           `json:"addr"`      // the bound address (host:port)
	Token    string           `json:"token"`     // session token
	Profiles []ProfileStatus  `json:"profiles"`
	ConnectURLs []string      `json:"connect_urls"` // addresses the phone can use
}

// ProfileStatus is one served profile, for display.
type ProfileStatus struct {
	Name    string `json:"name"`
	Project string `json:"project"`
	Mode    string `json:"mode"`
}

// Start binds a gateway on addr with the given profiles. token may be empty (a
// random one is minted). It's an error to start when already running.
func (c *Controller) Start(addr, token string, specs []ProfileSpec) (Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return c.statusLocked(), fmt.Errorf("already running on %s", c.addr)
	}
	host, err := BuildHost(c.cfg, specs)
	if err != nil {
		return Status{}, err
	}
	factory, reg := gateway.NewHostHandlerFactory(host)
	srv := gateway.NewServer(c.cfg.Version, strings.TrimSpace(token), factory, reg)

	if strings.TrimSpace(addr) == "" {
		addr = ":8787"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return Status{}, fmt.Errorf("listen %s: %w", addr, err)
	}
	c.httpSrv = &http.Server{Handler: srv.Routes()}
	c.ln = ln
	c.running = true
	c.addr = ln.Addr().String()
	c.token = srv.Token()
	c.profs = host.Profiles()

	go func() {
		_ = c.httpSrv.Serve(ln)
	}()
	return c.statusLocked(), nil
}

// StartAll starts the gateway sharing EVERY binny project (backend + local) as a
// profile, in the given mode. This is the Desktop path: no per-project selection.
func (c *Controller) StartAll(addr, token string, mode app.Mode) (Status, error) {
	specs := AllProjectSpecs(c.cfg.Client, mode)
	if len(specs) == 0 {
		return Status{}, fmt.Errorf("no projects to share — open or decompile one first")
	}
	return c.Start(addr, token, specs)
}

// Stop shuts the gateway down. Safe to call when already stopped.
func (c *Controller) Stop() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return c.statusLocked()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = c.httpSrv.Shutdown(ctx)
	c.running = false
	c.httpSrv = nil
	c.ln = nil
	c.profs = nil
	return c.statusLocked()
}

// Status returns the current snapshot.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.statusLocked()
}

// Token returns the active session token (empty when stopped).
func (c *Controller) Token() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (c *Controller) statusLocked() Status {
	st := Status{Running: c.running, Addr: c.addr, Token: c.token}
	for _, p := range c.profs {
		st.Profiles = append(st.Profiles, ProfileStatus{Name: p.Name, Project: p.ProjectNm, Mode: string(p.Mode)})
	}
	if c.running {
		st.ConnectURLs = connectURLs(c.addr)
	}
	return st
}

// connectURLs lists candidate base URLs the phone can use to reach this host:
// each non-loopback interface address plus the bound port, and loopback for
// same-machine testing.
func connectURLs(bound string) []string {
	_, port, err := net.SplitHostPort(bound)
	if err != nil {
		return nil
	}
	var urls []string
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() {
				continue
			}
			ip := ipnet.IP
			if ip.To4() == nil {
				continue // keep it to IPv4 for a clean phone entry
			}
			urls = append(urls, fmt.Sprintf("http://%s:%s", ip.String(), port))
		}
	}
	urls = append(urls, fmt.Sprintf("http://127.0.0.1:%s", port))
	return urls
}

// --- project resolution (shared) ---

// ResolveProject turns a reference into an attached *api.Project. It accepts a
// backend id, an explicit "local:<sha>" id, or a bare sha naming a local
// decompile in the on-disk store.
func ResolveProject(client *api.Client, ref string) (*api.Project, error) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, store.LocalIDPrefix) {
		return loadLocalProject(strings.TrimPrefix(ref, store.LocalIDPrefix))
	}
	if looksLikeSha(ref) {
		if meta, err := store.Load(ref); err == nil {
			return localProjectFromMeta(*meta), nil
		}
	}
	proj, err := client.GetProject(ref)
	if err != nil {
		return nil, fmt.Errorf("open project %q: %w", ref, err)
	}
	return proj, nil
}

func loadLocalProject(sha string) (*api.Project, error) {
	meta, err := store.Load(sha)
	if err != nil {
		return nil, fmt.Errorf("no local project for %q: %w", sha, err)
	}
	return localProjectFromMeta(*meta), nil
}

func looksLikeSha(ref string) bool {
	if len(ref) < 8 {
		return false
	}
	for _, c := range ref {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func localProjectFromMeta(meta store.Meta) *api.Project {
	if meta.Kind == store.KindAPK {
		return &api.Project{
			ID: store.LocalID(meta.Sha256), Kind: api.KindAPK, Name: meta.Name,
			OriginalFilename: meta.Name, SizeBytes: meta.SizeBytes, Sha256: meta.Sha256,
			Status: "READY", AnalysisMode: "MALWARE", PackageName: meta.PackageName, CreatedAt: meta.CreatedAt,
		}
	}
	arch := meta.Processor
	if arch == "" {
		arch = meta.Language
	}
	return &api.Project{
		ID: store.LocalID(meta.Sha256), Kind: api.KindBIN, Name: meta.Name,
		OriginalFilename: meta.Name, SizeBytes: meta.SizeBytes, Sha256: meta.Sha256,
		Status: "READY", AnalysisMode: "MALWARE", Arch: arch,
		ExecutableFormat: meta.Format, LanguageID: meta.Language, CreatedAt: meta.CreatedAt,
	}
}

func profileName(projName string, i int) string {
	base := strings.ToLower(strings.TrimSpace(projName))
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r == ' ', r == '-', r == '_', r == '.':
			return '-'
		default:
			return -1
		}
	}, base)
	if base == "" {
		base = fmt.Sprintf("profile-%d", i+1)
	}
	return base
}
