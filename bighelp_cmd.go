package main

// `binny bighelp` — serve binny directly to the bighelp app, with no Hermes.
//
// binny is already an agent harness; this stands up the Hermes-native transport
// bighelp speaks (HTTP bootstrap + /api/ws JSON-RPC) and backs each chat session
// with a real binny Engine. The CLI is the headless way to run it; Binny Desktop
// drives the same gateway from its menus (see internal/serve /api/bighelp/*).

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

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/auth"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/gateway"
	"openbin.ai/binny/internal/gwhost"
)

func runBighelp(args []string) error {
	fs := flag.NewFlagSet("binny bighelp", flag.ContinueOnError)
	addr := fs.String("addr", ":8787", "listen address for the gateway (host:port)")
	project := fs.String("project", "", "project(s) to serve as profiles: backend id, local:<sha>, or a local sha (comma-separated)")
	mode := fs.String("mode", "malware", "analysis lens for the profile(s): malware or vuln")
	sample := fs.String("sample", "", "raw sample path, enabling the sandbox/decompile tools for the profile")
	token := fs.String("token", "", "fixed session token (default: a random one, printed on start)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: binny bighelp --project <id> [flags]

Serves binny to the bighelp app over the Hermes-native transport (no Hermes
needed). Point the phone's "Add a computer" at this host's address; it connects
ungated, lists the profile(s) below, and chats with binny backed by a real
engine. Binny Desktop can start/stop this from its Mobile menu instead.

  binny bighelp --project local:<sha>            serve one project as a profile
  binny bighelp --project a,b --mode vuln        several projects, vuln lens
  binny bighelp --addr 0.0.0.0:8787              bind all interfaces (Tailscale)

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

	var specs []gwhost.ProfileSpec
	for _, ref := range splitCSV(*project) {
		specs = append(specs, gwhost.ProfileSpec{ProjectRef: ref, Mode: am, Sample: strings.TrimSpace(*sample)})
	}

	gcfg := gwhost.Config{Endpoints: ep, Cfg: cfg, Client: client, Version: version}
	host, err := gwhost.BuildHost(gcfg, specs)
	if err != nil {
		return err
	}
	factory, reg := gateway.NewHostHandlerFactory(host)
	srv := gateway.NewServer(version, strings.TrimSpace(*token), factory, reg)

	httpSrv := &http.Server{Handler: srv.Routes()}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ln, err := listen(*addr)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "binny bighelp: serving %d profile(s) on %s\n", len(host.Profiles()), ln.Addr())
	for _, p := range host.Profiles() {
		fmt.Fprintf(os.Stderr, "  profile %q → %s (%s)\n", p.Name, p.ProjectNm, p.Mode)
	}
	fmt.Fprintf(os.Stderr, "binny bighelp: session token: %s\n", srv.Token())
	fmt.Fprintf(os.Stderr, "binny bighelp: add this computer on the phone at http://<this-host>:%s\n", portOf(ln.Addr().String()))

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

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func listen(addr string) (net.Listener, error) {
	if strings.TrimSpace(addr) == "" {
		addr = ":8787"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return ln, nil
}

func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return addr
}
