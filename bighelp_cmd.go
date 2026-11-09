package main

// `binny bighelp` — serve binny directly to the bighelp app, with no Hermes.
//
// binny is already an agent harness; this stands up the Hermes-native transport
// bighelp speaks (HTTP bootstrap + /api/ws JSON-RPC) and backs each chat session
// with a real binny Engine. The phone connects to this host over the LAN or
// Tailscale, picks a profile (one per project+mode), and chats with binny.

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/auth"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/gateway"
)

func runBighelp(args []string) error {
	fs := flag.NewFlagSet("binny bighelp", flag.ContinueOnError)
	addr := fs.String("addr", ":8787", "listen address for the gateway (host:port)")
	project := fs.String("project", "", "project to serve as a profile: a backend id, local:<sha>, or a local decompile sha (repeatable via comma)")
	mode := fs.String("mode", "malware", "analysis lens for the profile(s): malware or vuln")
	sample := fs.String("sample", "", "raw sample path, enabling the sandbox/decompile tools for the profile")
	token := fs.String("token", "", "fixed session token (default: a random one, printed on start)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: binny bighelp --project <id> [flags]

Serves binny to the bighelp app over the Hermes-native transport (no Hermes
needed). Point the phone's "Add a computer" at this host's address; it connects
ungated, lists the profile(s) below, and chats with binny backed by a real
engine.

  binny bighelp --project local:<sha>            serve one project as a profile
  binny bighelp --project a,b --mode vuln        several projects, vuln lens
  binny bighelp --addr 0.0.0.0:8787              bind all interfaces (Tailscale)

Over Tailscale, run this on your analysis box and add its tailnet address on the
phone. Needs a configured LLM provider (BYOK) just like 'binny'.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if strings.TrimSpace(*project) == "" {
		fs.Usage()
		return fmt.Errorf("missing --project")
	}

	ep := config.LoadEndpoints()
	cfg, _, err := config.Load()
	if err != nil {
		return err
	}
	toks, err := auth.NewTokenSource(ep)
	if err != nil {
		return fmt.Errorf("auth: %w (run 'openbin login' for backend projects)", err)
	}
	client := api.New(ep, toks)

	am := app.ModeMalware
	if strings.EqualFold(*mode, "vuln") || strings.EqualFold(*mode, "vuln_research") {
		am = app.ModeVuln
	}

	// Build one profile per project id.
	var profiles []gateway.Profile
	ids := splitCSV(*project)
	for i, id := range ids {
		proj, err := resolveProject(client, id)
		if err != nil {
			return err
		}
		profiles = append(profiles, gateway.Profile{
			Name:      profileName(proj.Name, i),
			Display:   proj.Name,
			IsDefault: i == 0,
			Mode:      am,
			ProjectID: proj.ID,
			ProjectNm: proj.Name,
		})
	}

	host := &bighelpHost{
		ep: ep, cfg: cfg, client: client,
		sample: strings.TrimSpace(*sample),
		projByProfile: indexProjects(profiles),
	}

	factory, sessReg := gateway.NewHostHandlerFactory(host)
	srv := gateway.NewServer(version, strings.TrimSpace(*token), factory, sessReg)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *addr, err)
	}
	httpSrv := &http.Server{Handler: srv.Routes()}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Fprintf(os.Stderr, "binny bighelp: serving %d profile(s) on %s\n", len(profiles), ln.Addr())
	for _, p := range profiles {
		fmt.Fprintf(os.Stderr, "  profile %q → %s (%s)\n", p.Name, p.ProjectNm, p.Mode)
	}
	fmt.Fprintf(os.Stderr, "binny bighelp: session token: %s\n", srv.Token())
	fmt.Fprintf(os.Stderr, "binny bighelp: on the phone, add this computer at http://<this-host>:%s\n", portOf(ln.Addr().String()))

	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sh)
	}()
	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// bighelpHost implements gateway.Host: it maps a profile to a binny project and
// builds an engine-backed runtime per session.
type bighelpHost struct {
	ep            config.Endpoints
	cfg           *config.Config
	client        *api.Client
	sample        string
	projByProfile map[string]gateway.Profile
}

func (h *bighelpHost) Profiles() []gateway.Profile {
	out := make([]gateway.Profile, 0, len(h.projByProfile))
	for _, p := range h.projByProfile {
		out = append(out, p)
	}
	return out
}

func (h *bighelpHost) NewSessionRuntime(profile gateway.Profile) (gateway.Runtime, error) {
	proj, err := resolveProject(h.client, profile.ProjectID)
	if err != nil {
		return nil, err
	}
	// Resolve the provider the way NewSession does.
	prov := h.cfg.Find(h.cfg.DefaultProvider)
	if prov == nil && len(h.cfg.Providers) > 0 {
		prov = &h.cfg.Providers[0]
	}
	if prov == nil {
		return nil, fmt.Errorf("no LLM provider configured (run 'binny' once to set one up)")
	}
	sess := &app.Session{
		Endpoints:  h.ep,
		Config:     h.cfg,
		API:        h.client,
		Project:    proj,
		Mode:       profile.Mode,
		Autonomy:   app.Autonomous,
		Provider:   prov,
		Model:      h.cfg.DefaultModel,
		SamplePath: h.sample,
	}
	rt, err := agent.NewGatewayRuntime(sess, h.client)
	if err != nil {
		return nil, err
	}
	return &runtimeAdapter{rt: rt}, nil
}

// runtimeAdapter bridges agent.GatewayRuntime to gateway.Runtime. The two event
// callback types are structurally identical; this adapts the one to the other.
type runtimeAdapter struct{ rt *agent.GatewayRuntime }

func (a *runtimeAdapter) Submit(ctx context.Context, text string, io *gateway.TurnIO) error {
	return a.rt.Submit(ctx, text, &agent.TurnIO{
		Emit: func(t string, p any) error { return io.Emit(t, p) },
		Ask:  func(c context.Context, q string, ch []string) (string, error) { return io.Ask(c, q, ch) },
	})
}
func (a *runtimeAdapter) Close() { a.rt.Close() }

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
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

func indexProjects(ps []gateway.Profile) map[string]gateway.Profile {
	m := make(map[string]gateway.Profile, len(ps))
	for _, p := range ps {
		m[p.Name] = p
	}
	return m
}

func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return addr
}
