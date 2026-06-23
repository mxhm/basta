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

The API key is visible inside the sandbox; the egress allowlist limits where it can be sent.

## Recipes

Each is a complete command; replace `<workspace>` and `<task>`. Verified under
basta 0.1.0.

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
