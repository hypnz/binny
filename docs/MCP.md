# BINNY over MCP

`binny mcp` serves BINNY's reverse-engineering capability over the **Model
Context Protocol** (stdio), so any MCP host can drive it: a
[Hermes](https://github.com/NousResearch/hermes-agent) computer (and therefore
the bighelp app on your phone), Claude Desktop, or any other MCP client.

The host's model is the analyst; BINNY supplies the tools and the project they
read. BINNY does not run its own model in this mode — except for the optional
`investigate` tool (see Phase 3), which runs BINNY's own loop end to end.

```
bighelp (phone)  ──Tailscale──▶  Hermes host  ──stdio MCP──▶  binny mcp
```

Nothing on the iOS side changes: bighelp already speaks Hermes' transport and
reaches the host over your home network, Tailscale, or HTTPS. The only setup is
on the host.

## What it serves

| Tools | When | Needs |
|---|---|---|
| **Read**: `get_metadata`, `list_functions`, `get_function`, `get_strings`, `get_imports`, `xrefs`, `reachability`, decompiled-source reads, APK manifest/code search | always | a project |
| **Sandbox**: `write_file`, `run`, `read_artifact` (hardened, networkless container; sample read-only at `/sample`, persistent `/work`) | `--sample` + Docker | Docker on the host |
| **Decompile**: `decompile_sample` (local Ghidra headless, hot-swapped into the read tools) | `--sample` + Docker, BIN projects | Docker on the host |
| **Investigate**: `investigate` (runs BINNY's whole triage→investigate→report loop, returns the report) | `--agent` | a configured LLM provider (BYOK) |

Missing Docker or no `--sample` degrades to the read-only server with a note on
stderr, rather than failing.

## Quick start

Build BINNY on the host and pick a project:

```sh
go build -o binny .
binny mcp --list                     # projects you can open
```

Serve one project:

```sh
# read-only (cloud or local project)
binny mcp --project local:abc123def456

# + sandbox & decompile (needs Docker + the raw file)
binny mcp --project local:abc123def456 --sample /samples/malware.bin

# + the whole-investigation tool (needs a BYOK provider)
binny mcp --project local:abc123def456 --sample /samples/malware.bin --agent --mode malware
```

Diagnostics go to **stderr**; stdout is the JSON-RPC stream, so never print to it.

### Project references

- **Backend project**: the OpenBin/OpenAPK id (needs `openbin login` on the host).
- **Local decompile**: `local:<sha>` or the bare sha — produced by `binny` /
  `binny desktop` `/decompile`, read from disk.

## Registering on a Hermes host

Hermes adds capabilities to a profile as MCP servers. Register BINNY as a
**stdio** server (Hermes spawns it locally, so there's no extra listener and no
token to manage — the only network hop is phone → Hermes):

```http
POST /api/mcp/servers
{
  "name": "binny",
  "profile": "<your-profile>",
  "command": "binny",
  "args": ["mcp", "--project", "local:abc123def456", "--sample", "/samples/malware.bin"],
  "env": {}
}
```

Enable it for the profile:

```http
PUT /api/mcp/servers/binny/enabled
{ "profile": "<your-profile>", "enabled": true }
```

Open that profile in bighelp and you're driving BINNY from your phone. See
`docs/hermes/REFERENCE.md` on the host for the exact MCP config shape (stdio vs
HTTP, `auth` options).

### HTTP instead of stdio (separate Tailscale node)

If BINNY runs on a different machine from Hermes, run it behind an MCP HTTP
transport and point Hermes at it over the tailnet
(`http://binny-host.<tailnet>.ts.net:PORT`). Tailscale ACLs are your access
control; add a bearer header via Hermes' `auth: "header"` if you want
defence-in-depth. (stdio co-located with Hermes is simpler and recommended.)

## The `investigate` tool (Phase 3)

With `--agent`, BINNY exposes a single `investigate` tool that runs its **own**
triage → investigate → synthesize loop autonomously and returns the finished
report — classification, evidence-grounded findings, IOCs, and written sections
in BINNY's format. Use it to delegate a whole analysis in one call; use the
individual tools for targeted questions.

Arguments:

- `instructions` (string, optional) — extra focus, fed in as analyst intel
  (e.g. "focus on C2 and persistence", "is the heap overflow in parse() reachable?").
- `extend_on_cap` (bool, optional) — raise the spend budget once and continue if
  a cap is hit, instead of wrapping up early.

It runs **Autonomous** (no interactive checkpoints), answers any stray
`ask_user` with a proceed-on-best-judgment note so an unattended run never
hangs, and stops the moment the draft is ready. A run can take several minutes
and many model rounds; progress is logged to stderr (visible in the host's
logs). Because it runs BINNY's model, it spends your BYOK tokens — pick the
model with `--model` and the lens with `--mode malware|vuln`.

## Notes

- **Docker** is only needed on the host for the sandbox and `decompile_sample`
  tools. Large firmware can OOM Ghidra; give the host enough RAM.
- **Auth**: backend projects need `openbin login` on the host; local projects
  need none. The `investigate` tool needs a provider configured in BINNY
  (`binny` once, interactively, to set BYOK).
- **Safety**: in `--agent` mode a provider's safety classifier may decline
  malware RE; the run stops with a clear note and you can retry with a different
  `--model`/provider.
