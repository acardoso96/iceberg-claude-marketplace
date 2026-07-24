# secret-guard

A security gate for Claude Code that implements **Article 5 (security)** of the project
constitution. It registers a single **`PreToolUse`** hook that runs **before** every tool
call and **denies** the ones that would put sensitive information or the file system at risk.

> **Important:** a plugin hook is not scoped to "its own" plugin. Once `secret-guard` is
> installed, its gate applies to the **whole session** — any `Read`, `Grep`, `Bash`,
> `Write`, etc., regardless of which plugin, skill or subagent triggers it. It is a
> *cross-cutting* control; that is why it should be declared a **mandatory install** for
> every developer.

## What it blocks

| Tool(s) | Protection |
|---|---|
| `Read`, `Grep`, `Glob` | Denies reading secrets / `clientId` / sensitive config |
| `Bash` | Denies reading secrets via the shell (`cat`/`type`/`Get-Content`…), environment-variable dumps, and **vetoes destructive commands** (`rm -rf`, `del /s`, `Remove-Item -Recurse -Force`…) |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | Denies **writing** real secrets into files |

**Content-aware policy for config files:** configuration files
(`*.properties`, `application*.yml`, `appsettings*.json`, `*.ini`, `*.toml`, `*.config`…) are
blocked **only when they contain** a real sensitive value (`clientId`, `clientSecret`,
`password`, `apiKey`, `connectionString`, private keys…). A config file with no secrets can be
read normally. Files dedicated to secrets (`.env`, `*.pem`, `*.key`, `credentials`,
`id_rsa`…) are **always** blocked.

Because a `PreToolUse` hook can only allow or deny (it cannot redact just the value), a file
that contains secrets has its read denied entirely, and the message guides Claude to **ask the
user for the specific value** instead.

## Installation

From the Iceberg marketplace:

```
/plugin marketplace add <repo-url-or-path>
/plugin install secret-guard@iceberg-claude-marketplace
```

Restart the session so the hook becomes active.

**Requirement:** `node` must be available on the `PATH` (the hook runs as
`node security-guard.cjs`). The script is **dependency-free CommonJS**, compatible with
Node 12+, so it runs with the system `node` even if it is old. On npm-based Claude Code
installs it is already present. If `node` is not on the `PATH`, the hook does not start and
**fails open** (the read proceeds) — watch out for this case.

## Per-project tuning (optional)

The patterns ship with sensible embedded defaults and work with no configuration. To extend
them for a specific project, create `.claude/secret-guard.json` at the project root:

```json
{
  "dedicatedSecretFiles": ["my-custom-secrets\\.txt$"],
  "configFiles": ["\\.custom-config$"],
  "allowlist": ["fixtures[\\\\/].*\\.env$"]
}
```

- `dedicatedSecretFiles` / `configFiles`: additional **regex** patterns (case-insensitive).
- `allowlist`: paths that are **always** allowed (useful for test fixtures with fake secrets).

## How it works (hook contract)

The `scripts/security-guard.cjs` script receives the event JSON on **stdin**
(`tool_name`, `tool_input`, `cwd`, …) and:

- to **deny**: prints to stdout the JSON with
  `hookSpecificOutput.permissionDecision = "deny"` and exits with code `0`;
- to **allow**: exits with code `0` and no output (the normal permission flow applies).

On any internal error the hook **fails open** (allows) so it can never brick a session.

## Quick script test

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf build"}}' | node scripts/security-guard.cjs
# → { "hookSpecificOutput": { ... "permissionDecision": "deny" ... } }

echo '{"tool_name":"Bash","tool_input":{"command":"npm test"}}' | node scripts/security-guard.cjs
# → (no output = allowed)
```
