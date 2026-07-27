# Agent recipes

Each recipe is the basta flags to launch one coding-agent CLI. Four things to set:

- **Auth**: `--seed` the *specific* auth file(s) into the fresh tmpfs `$HOME`
  (ephemeral). Seed individual files, not the config dir, since basta refuses
  symlinks in a seed tree. (`--persist` if a refreshed token must survive runs.)
- **Model endpoint**: cloud API: `--allow-sni <host>`; local server on **this**
  machine: `--allow-loopback <port>`; on **another** LAN host: `--allow <ip>:<port>`.
  A same-machine server always uses loopback (see
  [Local model](#local-model-omp-pi-or-any-openai-compatible-cli)).
- **Own sandbox off**: disable the agent's internal sandbox / approval gate
  (basta is the boundary); flag per agent below.
- **Locked config**: the workspace lock makes `.claude` / `.vscode` /
  `.mcp.json` read-only; `--unlock .claude` etc.
- **Web UI**: a harness that serves a local web UI a host browser must reach
  (e.g. openscience) needs `--publish PORT` — it forwards host `127.0.0.1:PORT`
  into the sandbox's `127.0.0.1:PORT` (loopback-scoped), while egress stays
  filtered. See [OpenScience](#openscience-wopenscience).

The API key is visible inside the sandbox; the egress allowlist limits where it can be sent.

## Recipes

Each is a complete command; replace `<workspace>` and `<task>`. Verified under
basta 0.1.2.

**To add a recipe:** copy a block and fill in the four parts: egress endpoints,
auth `--seed`s, the own-sandbox-off flag, and the command.

### Claude Code

**Egress:** `api.anthropic.com` only. It carries both inference and OAuth token
refresh (verified). Set `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` to skip the
telemetry hosts.

```
basta --allow-sni api.anthropic.com \
    --env CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    --seed ~/.claude/.credentials.json:.claude/.credentials.json \
    --seed ~/.claude.json:.claude.json \
    --unlock .claude \
    <workspace> -- claude -p --dangerously-skip-permissions "<task>"
```

`--dangerously-skip-permissions` disables Claude's own approval gate; `--unlock
.claude` lets it write project state.

### Codex (OpenAI)

**Egress:** `chatgpt.com`, `api.openai.com`, `auth.openai.com` (login/refresh).

```
basta --allow-sni chatgpt.com --allow-sni api.openai.com --allow-sni auth.openai.com \
    --seed ~/.codex/auth.json:.codex/auth.json \
    --seed ~/.codex/config.toml:.codex/config.toml \
    <workspace> -- codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check "<task>"
```

`codex exec` is non-interactive; `--dangerously-bypass-approvals-and-sandbox`
disables Codex's own Landlock+seccomp sandbox; `--skip-git-repo-check` allows
non-git directories.

### Antigravity (`agy`)

**Egress:** `daily-cloudcode-pa.googleapis.com`, `www.googleapis.com`,
`oauth2.googleapis.com` (refresh).

```
basta --allow-sni daily-cloudcode-pa.googleapis.com --allow-sni www.googleapis.com \
    --allow-sni oauth2.googleapis.com \
    --seed ~/.gemini/antigravity-cli/antigravity-oauth-token:.gemini/antigravity-cli/antigravity-oauth-token \
    --seed ~/.gemini/antigravity-cli/installation_id:.gemini/antigravity-cli/installation_id \
    --seed ~/.gemini/antigravity-cli/settings.json:.gemini/antigravity-cli/settings.json \
    --seed ~/.gemini/config:.gemini/config \
    <workspace> -- agy -p --dangerously-skip-permissions "<task>"
```

### Local model (omp, pi, or any OpenAI-compatible CLI)

No external egress. **A local model on the same machine is always reached with
`--allow-loopback PORT` and base URL `http://127.0.0.1:PORT`, never `--allow`,
whatever address the server binds.** Common ports: llama.cpp `llama-server`
`8080`, vLLM `8000`.

| Server location | basta flag | Base URL |
|---|---|---|
| Same machine (any local port) | `--allow-loopback PORT` | `http://127.0.0.1:PORT` |
| Another LAN host | `--allow <ip>:PORT` | `http://<ip>:PORT` |

Why: the sandbox runs in its own network namespace that carries the host's own
addresses, so from inside both `127.0.0.1` and the host's LAN IP point at the
sandbox, not the host. `--allow-loopback PORT` forwards the sandbox's
`127.0.0.1:PORT` to the host's; a direct `--allow <host-ip>` fails and `--allow
127.0.0.1:PORT` is refused. `--allow <ip>:PORT` is for a server on a *different* host.

```
# llama.cpp llama-server on this machine (default port 8080)
basta --allow-loopback 8080 <workspace> -- <agent> -p "<task>"

# A keyed OpenAI-compatible server (vLLM/llama.cpp) + seeded config
basta --allow-loopback 8000 --env LLAMACPP_API_KEY \
    --seed <model-config>:<dest under $HOME> \
    <workspace> -- <agent> -p "<task>"
```

Point the agent's base URL at `http://127.0.0.1:<port>`. `--env LLAMACPP_API_KEY`
(no `=value`) forwards a server key from your shell, so it isn't written to disk.

### OpenScience (`wopenscience`)

Autonomous research agent with a **local web UI** (Bun server on `127.0.0.1:4096`)
that autonomously **writes and runs code** (bash/Python/R/Jupyter). OpenScience is
*not* a security boundary (its own docs say run it in a container/VM) and defaults to
auto-allowing every tool call — so basta is the sole containment. Two basta defaults
carry the safety here: the **env scrub** (only `ANTHROPIC_API_KEY` crosses in; every
other host credential — AWS/GitHub/Modal/… — is stripped) and the **tmpfs `$HOME`**
(the host's real `$HOME` is invisible; only the paths bound below exist inside).

**UI:** `--publish 4096` forwards host `127.0.0.1:4096` into the sandbox so your
browser reaches the workspace. Keep the sandbox port equal to the host port so the
auto-opened `http://localhost:4096` resolves; `--port 4096` pins OpenScience to it.

**Egress (open — the full toolbox):** the model provider, web search, the
literature/bio databases, and the package registries. The command below covers the
common connectors; OpenScience ships ~30 science connectors in total (chemistry,
omics, pathways, more genomics). For the rest, read the hostnames out of its
`science/connectors/**` sources — do **not** use OpenScience's own
`settings/network.ts` allowlist, which is advisory-only and lists hosts the code
doesn't actually fetch (it says `files.rcsb.org` where the code calls
`data.rcsb.org`). Trim any group you don't want (registries block installs; a missing
DB host just disables that connector). `api.anthropic.com` is the Anthropic SDK
default; swap/add `api.openai.com`, `generativelanguage.googleapis.com`,
`openrouter.ai` for other providers.

```
basta --publish 4096 \
    --allow-sni api.anthropic.com \
    --allow-sni mcp.exa.ai \
    --allow-sni export.arxiv.org --allow-sni api.crossref.org --allow-sni doi.org \
    --allow-sni api.openalex.org --allow-sni api.semanticscholar.org \
    --allow-sni europepmc.org --allow-sni api.biorxiv.org \
    --allow-sni eutils.ncbi.nlm.nih.gov --allow-sni www.ncbi.nlm.nih.gov \
    --allow-sni pubmed.ncbi.nlm.nih.gov --allow-sni pubchem.ncbi.nlm.nih.gov \
    --allow-sni www.ebi.ac.uk --allow-sni alphafold.ebi.ac.uk \
    --allow-sni rest.uniprot.org --allow-sni data.rcsb.org --allow-sni search.rcsb.org \
    --allow-sni rest.ensembl.org --allow-sni string-db.org \
    --allow-sni reactome.org --allow-sni rest.kegg.jp \
    --allow-sni pypi.org --allow-sni files.pythonhosted.org \
    --allow-sni registry.npmjs.org --allow-sni conda.anaconda.org \
    --allow-sni cran.r-project.org \
    --allow-sni github.com --allow-sni raw.githubusercontent.com \
    --env ANTHROPIC_API_KEY \
    --env OPENSCIENCE_DISABLE_MODELS_FETCH=1 \
    ~/.openscience:ro ~/.openscience/state \
    ~/.config/openscience ~/.local/share/openscience \
    <workspace> \
    -- openscience --port 4096 "<goal>"
```

`~/.openscience:ro` binds the ~152 MB binary read-only (a bind, **not** `--seed` —
seed copies into tmpfs RAM); `~/.openscience/state` layers RW over it.
`OPENSCIENCE_DISABLE_MODELS_FETCH=1` drops the `models.dev` fetch. The state dirs are
host paths, so login/sessions survive across runs; drop them for an ephemeral session.

**Residual egress holes (open by design here):** OpenScience's `webfetch` tool fetches
any URL the model picks, and user-configured MCP servers dial arbitrary hosts. nft
still drops anything off the allowlist, and the env scrub means there are no stray
creds to exfil — but any *allowed* host doubles as an exfil channel. To tighten: drop
the registry lines (block installs, pre-provision a fixed env instead), disable
`webfetch` in `openscience.json`, and leave MCP unconfigured. Harden `openscience.json`
too: `permission.bash: "ask"` to override the auto-allow default, and don't log into
Atlas (BYOK/local only).

**MCP OAuth:** `--publish` takes a single port, so the fixed MCP-OAuth callback
(`127.0.0.1:19876`) cannot be published in the same launch — leave MCP unconfigured,
or use the UI port for the workspace and complete MCP auth outside the sandbox.
**GPU:** add `--gpu` only on a GPU box for real local compute; the app itself needs
none. **io_uring:** basta's seccomp denylist blocks `io_uring*`, but the Bun binary
starts fine under it (verified); if a future build errors on `io_uring_setup`, add
`--allow-syscall io_uring_setup,io_uring_enter,io_uring_register`.
