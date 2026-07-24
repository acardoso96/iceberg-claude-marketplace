#!/usr/bin/env node
/**
 * secret-guard — PreToolUse security gate for Claude Code (constitution, Article 5).
 *
 * Reads the PreToolUse hook payload from stdin and decides whether to DENY a tool
 * call that would:
 *   - READ secrets / clientId / sensitive config (Read, Grep, Glob, or shell readers via Bash),
 *   - WRITE a real secret into a file (Write, Edit, MultiEdit, NotebookEdit),
 *   - run a DESTRUCTIVE command (rm -rf, del /s, Remove-Item -Recurse -Force, ...).
 *
 * Contract (from the Claude Code hooks docs):
 *   - stdin: JSON with { tool_name, tool_input, cwd, ... }
 *   - to DENY: print the deny JSON to stdout and exit 0.
 *   - to ALLOW / no-decision: exit 0 with NO stdout (normal permission flow applies).
 *   - never use exit 1 to block (exit != 2 and != 0-with-deny is non-blocking).
 *
 * Written in CommonJS with no `node:` import prefix and no syntax newer than Node 12,
 * so it runs under whatever `node` the developer has on PATH (the hook is invoked as
 * `node <this-file>`, which may be an older system Node, not the one running Claude Code).
 *
 * Zero dependencies (Node built-ins only). Fails OPEN on any internal error so a bug
 * here can never brick a session — the cost is that a broken hook silently disables
 * the guard, which is why there is a unit-test battery (see README / test-samples).
 */

"use strict";

const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// Pattern configuration (tunable). Optionally extended per-project via
// <CLAUDE_PROJECT_DIR>/.claude/secret-guard.json — see loadConfig().
// ---------------------------------------------------------------------------

const DEFAULTS = {
  // Files whose entire purpose is secrets → always denied on read.
  dedicatedSecretFiles: [
    /(^|[\\/])\.env(\.[\w.-]+)?$/i, //  .env, .env.local, .env.production
    /\.(pem|key|pfx|p12|p8|jks|keystore|ppk|asc|gpg)$/i,
    /(^|[\\/])id_(rsa|dsa|ecdsa|ed25519)$/i,
    /(^|[\\/])(credentials|\.git-credentials|\.netrc|_netrc|\.npmrc|\.pypirc)$/i,
    /(^|[\\/])secrets?(\.[\w.-]+)?$/i, //  secret, secrets, secrets.json
    /secret[\w-]*\.(json|ya?ml|txt|properties)$/i,
    /service[-_]account[\w-]*\.json$/i,
    /[\\/]\.ssh[\\/]/i,
    /[\\/]\.aws[\\/]credentials$/i,
    /[\\/]\.docker[\\/]config\.json$/i,
  ],
  // Config files → content-aware: denied only when they actually contain a secret.
  configFiles: [
    /\.properties$/i,
    /\.(ya?ml)$/i,
    /appsettings[\w.-]*\.json$/i,
    /(^|[\\/])(web|app)\.config$/i,
    /\.config$/i,
    /\.(ini|conf|cfg|toml|env)$/i,
  ],
  // Keys that name a secret (tested against the KEY token of a `key = value` line).
  sensitiveKeyRe:
    /(client[_-]?secret|client[_-]?id|pass(word|wd)?|pwd|api[_-]?key|secret[_-]?key|\bsecret\b|access[_-]?(key|token)|auth[_-]?token|\bbearer\b|private[_-]?key|connection[_-]?string|conn[_-]?str|\btoken\b|aws[_-]?(secret|access)[_-]?key|db[_-]?password|keystore[_-]?password)/i,
  // Values that are NOT real secrets (placeholders / env references / examples).
  placeholderRe:
    /^(\$\{[^}]*\}|%[^%]*%|\$env:\w+|\$[a-z_][a-z0-9_]*|<[^>]*>|null|nil|none|changeme|change_me|your[-_].*|example.*|xxx+|\*{2,}|todo|tbd|\.{3})$/i,
};

let cfg = DEFAULTS; // replaced by loadConfig() at startup

function toRe(source) {
  try {
    return new RegExp(source, "i");
  } catch (e) {
    return /^\b$/; // never-matching fallback for a bad user pattern
  }
}

function loadConfig() {
  const merged = {
    dedicatedSecretFiles: DEFAULTS.dedicatedSecretFiles.slice(),
    configFiles: DEFAULTS.configFiles.slice(),
    sensitiveKeyRe: DEFAULTS.sensitiveKeyRe,
    placeholderRe: DEFAULTS.placeholderRe,
    allowlist: [], // paths matching any of these are always allowed
  };
  try {
    const dir = process.env.CLAUDE_PROJECT_DIR;
    if (!dir) return merged;
    const p = path.join(dir, ".claude", "secret-guard.json");
    if (!fs.existsSync(p)) return merged;
    const raw = JSON.parse(fs.readFileSync(p, "utf8"));
    if (Array.isArray(raw.dedicatedSecretFiles))
      merged.dedicatedSecretFiles = merged.dedicatedSecretFiles.concat(
        raw.dedicatedSecretFiles.map(toRe)
      );
    if (Array.isArray(raw.configFiles))
      merged.configFiles = merged.configFiles.concat(raw.configFiles.map(toRe));
    if (Array.isArray(raw.allowlist)) merged.allowlist = raw.allowlist.map(toRe);
  } catch (e) {
    /* malformed override → fall back to defaults */
  }
  return merged;
}

// ---------------------------------------------------------------------------
// Output helpers. fs.writeSync(1, ...) is synchronous, guaranteeing the deny
// JSON is flushed before process.exit(0) (process.stdout to a pipe is async and
// could be truncated by an immediate exit).
// ---------------------------------------------------------------------------

function deny(reason) {
  const payload = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "secret-guard: " + reason,
    },
  };
  try {
    fs.writeSync(1, JSON.stringify(payload));
  } catch (e) {
    /* if we cannot emit the deny, fall through to exit(0) = allow */
  }
  process.exit(0);
}

function allow() {
  process.exit(0); // no stdout → no decision → normal permission flow
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

function matchAny(regexList, str) {
  return (
    Array.isArray(regexList) &&
    regexList.some(function (re) {
      return re.test(str);
    })
  );
}

function basenameOf(p) {
  const norm = String(p).replace(/\\/g, "/");
  return norm.split("/").pop() || norm;
}

function resolvePath(p, cwd) {
  return path.isAbsolute(p) ? p : path.resolve(cwd || process.cwd(), p);
}

function isPlaceholderValue(val) {
  if (val === "") return true;
  if (/^(true|false|yes|no|on|off|enabled|disabled|\d+(\.\d+)?)$/i.test(val))
    return true; // config flags / numbers are not secrets
  return cfg.placeholderRe.test(val);
}

/**
 * Scan config/text content for a real secret. Returns the offending key name
 * (or a label) when found, else null.
 */
function scanTextForSecret(text) {
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(text)) return "private key";
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.charAt(0) === "#" || line.charAt(0) === ";" || line.indexOf("//") === 0)
      continue;
    const m = line.match(/^["']?([A-Za-z0-9_.\-]+)["']?\s*[:=]\s*(.*)$/);
    if (!m) continue;
    const key = m[1];
    let val = m[2].trim();
    val = val.replace(/,\s*$/, "").trim(); // trailing JSON comma
    val = val.replace(/^["']|["']$/g, "").trim(); // surrounding quotes
    if (!cfg.sensitiveKeyRe.test(key)) continue;
    if (isPlaceholderValue(val)) continue;
    if (val.length < 3) continue; // too short to be a real secret
    return key;
  }
  return null;
}

/** Read up to 64 KB of a file and scan it. Returns matched key/label or null. */
function configContainsSecret(absPath) {
  let text;
  try {
    const fd = fs.openSync(absPath, "r");
    try {
      const buf = Buffer.alloc(65536);
      const n = fs.readSync(fd, buf, 0, buf.length, 0);
      text = buf.toString("utf8", 0, n);
    } finally {
      fs.closeSync(fd);
    }
  } catch (e) {
    return null; // unreadable / non-existent / binary → don't block on content
  }
  return scanTextForSecret(text);
}

/** Classify a file path for a READ. Returns a deny reason, or null to allow. */
function classifyFileRead(filePath, cwd) {
  const norm = String(filePath).replace(/\\/g, "/");
  const base = basenameOf(filePath);
  if (matchAny(cfg.allowlist, norm) || matchAny(cfg.allowlist, base)) return null;
  if (matchAny(cfg.dedicatedSecretFiles, norm) || matchAny(cfg.dedicatedSecretFiles, base)) {
    return (
      "blocked read of '" +
      base +
      "': dedicated secrets file. Ask the user to share only the specific non-secret value you actually need."
    );
  }
  if (matchAny(cfg.configFiles, norm) || matchAny(cfg.configFiles, base)) {
    const hit = configContainsSecret(resolvePath(filePath, cwd));
    if (hit)
      return (
        "blocked read of '" +
        base +
        "': it contains a sensitive value (" +
        hit +
        "). Ask the user for the specific value instead of reading the whole file."
      );
  }
  return null;
}

// ---------------------------------------------------------------------------
// Bash inspection
// ---------------------------------------------------------------------------

const DESTRUCTIVE = [
  // rm with both -r and -f (any order, including combined -rf / -fr)
  [/\brm\b(?=[^\n]*\s-[^\s]*r)(?=[^\n]*\s-[^\s]*f)/i, "rm -r -f"],
  [/\b(del|erase)\b[^\n]*\s\/[sfq]/i, "del /s /f /q"],
  [/\brmdir\b[^\n]*\s\/s/i, "rmdir /s"],
  [/\bRemove-Item\b(?=[^\n]*-Recurse)(?=[^\n]*-Force)/i, "Remove-Item -Recurse -Force"],
  [/\bmkfs\b/i, "mkfs"],
  [/\bdd\b[^\n]*\bif=/i, "dd if="],
  [/>\s*\/dev\/sd[a-z]/i, "overwrite block device"],
  [/\bshred\b/i, "shred"],
  [/\bformat\b\s+[a-z]:/i, "format <drive>"],
  [/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, "fork bomb"],
  [/\bgit\s+clean\b[^\n]*-[a-z]*(df|fd)/i, "git clean -fd"],
];

function matchDestructive(cmd) {
  for (let i = 0; i < DESTRUCTIVE.length; i++) {
    if (DESTRUCTIVE[i][0].test(cmd)) return DESTRUCTIVE[i][1];
  }
  return null;
}

const ENV_EXFIL = [
  /(^|[|;&]\s*)printenv\s*($|[|;&])/i, //  bare printenv
  /(^|[|;&]\s*)env\s*($|[|;&])/i, //        bare env (not `env VAR=x cmd`)
  /\b(Get-ChildItem|gci|ls|dir|Get-Item)\s+env:/i,
  /(echo|printf|Write-Output|Write-Host)\s+["']?[$%]?\{?(env:)?\w*(secret|password|passwd|pwd|token|api[_-]?key|client[_-]?secret|access[_-]?key)\w*/i,
];

function matchEnvExfil(cmd) {
  return ENV_EXFIL.some(function (re) {
    return re.test(cmd);
  });
}

const READER_RE =
  /\b(cat|tac|type|more|less|head|tail|nl|strings|xxd|od|hexdump|gc|Get-Content|sort|rev|base64|grep|egrep|fgrep|rg|ag|ack|findstr|sed|awk)\b/i;

function bashReadsSecretFile(cmd, cwd) {
  const hasReader =
    READER_RE.test(cmd) ||
    /(^|[|;&]|\s)(source|\.)\s+\S/.test(cmd) || //  sourcing an env file
    /<\s*\S/.test(cmd); //                          input redirection
  if (!hasReader) return null;

  const tokens = cmd.split(/[\s"'`=(){}<>|;&]+/).filter(Boolean);
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (!/[./\\]/.test(tok)) continue; // only path-ish tokens
    const norm = tok.replace(/\\/g, "/");
    const base = basenameOf(tok);
    if (matchAny(cfg.allowlist, norm) || matchAny(cfg.allowlist, base)) continue;
    if (matchAny(cfg.dedicatedSecretFiles, norm) || matchAny(cfg.dedicatedSecretFiles, base)) {
      return (
        "blocked shell read of '" +
        base +
        "': dedicated secrets file. Ask the user for the specific value you need."
      );
    }
    if (matchAny(cfg.configFiles, norm) || matchAny(cfg.configFiles, base)) {
      const hit = configContainsSecret(resolvePath(tok, cwd));
      if (hit)
        return (
          "blocked shell read of '" + base + "': it contains a sensitive value (" + hit + ")."
        );
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Write inspection
// ---------------------------------------------------------------------------

function writeSecretHit(text) {
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(text)) return "private key";
  if (/\bAKIA[0-9A-Z]{16}\b/.test(text)) return "AWS access key id";
  if (
    /(password|pwd)\s*=\s*[^\s;"']{4,}/i.test(text) &&
    /(server|data source|host|initial catalog|database)\s*=/i.test(text)
  )
    return "connection string password";
  const keyHit = scanTextForSecret(text);
  if (keyHit) return keyHit;
  if (/\bBearer\s+[A-Za-z0-9._\-]{16,}\b/.test(text)) return "bearer token";
  return null;
}

// ---------------------------------------------------------------------------
// Grep / Glob helpers
// ---------------------------------------------------------------------------

// Strip glob metacharacters so an anchored file pattern still matches a target
// like `**/.env*` or `config/**/*.pem`.
function normalizeGlobTarget(str) {
  return String(str).replace(/\\/g, "/").replace(/[*?]/g, "").trim();
}

// True if any of the given path/pattern/glob components points at a dedicated
// secrets file. Components are tested separately (never concatenated) so a
// trailing space can't break the `$`-anchored patterns.
function anyComponentIsSecretFile(components) {
  for (let i = 0; i < components.length; i++) {
    const c = components[i];
    if (!c) continue;
    if (matchAny(cfg.dedicatedSecretFiles, normalizeGlobTarget(c))) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Per-tool handlers
// ---------------------------------------------------------------------------

function checkRead(input, cwd) {
  const fp = input.file_path || input.filePath;
  if (!fp) return allow();
  const reason = classifyFileRead(fp, cwd);
  return reason ? deny(reason) : allow();
}

function checkGrep(input) {
  const pattern = input.pattern || "";
  if (cfg.sensitiveKeyRe.test(pattern))
    return deny(
      "blocked grep: the search pattern targets secret material. Ask the user for the value directly instead of scanning for it."
    );
  if (anyComponentIsSecretFile([input.path, input.glob]))
    return deny("blocked grep: the target path is a dedicated secrets file.");
  return allow();
}

function checkGlob(input) {
  if (anyComponentIsSecretFile([input.pattern, input.path]))
    return deny("blocked glob: the pattern targets dedicated secrets files.");
  return allow();
}

function checkBash(input, cwd) {
  const cmd = input.command || "";
  if (!cmd) return allow();
  const destructive = matchDestructive(cmd);
  if (destructive)
    return deny(
      "blocked destructive command (" +
        destructive +
        "). Irreversible operations are vetoed by the security constitution (Article 5). Confirm the exact intent with the user and run it manually if truly required."
    );
  if (matchEnvExfil(cmd))
    return deny("blocked command: it would dump environment variables that may contain secrets.");
  const fileHit = bashReadsSecretFile(cmd, cwd);
  if (fileHit) return deny(fileHit);
  return allow();
}

function checkWrite(toolName, input) {
  const chunks = [];
  if (typeof input.content === "string") chunks.push(input.content);
  if (typeof input.new_string === "string") chunks.push(input.new_string);
  if (typeof input.new_source === "string") chunks.push(input.new_source);
  if (Array.isArray(input.edits)) {
    for (let i = 0; i < input.edits.length; i++) {
      const e = input.edits[i];
      if (e && typeof e.new_string === "string") chunks.push(e.new_string);
    }
  }
  const text = chunks.join("\n");
  if (!text) return allow();
  const hit = writeSecretHit(text);
  if (hit)
    return deny(
      "blocked " +
        toolName +
        ": the content includes what looks like a real secret (" +
        hit +
        "). Use an environment variable or a placeholder (e.g. ${VAR}) instead of a literal value."
    );
  return allow();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function main() {
  cfg = loadConfig();

  let raw = "";
  try {
    raw = fs.readFileSync(0, "utf8");
  } catch (e) {
    return allow();
  }
  if (!raw.trim()) return allow();

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (e) {
    return allow();
  }

  const toolName = payload.tool_name || "";
  const input = payload.tool_input || {};
  const cwd = payload.cwd || process.env.CLAUDE_PROJECT_DIR || process.cwd();

  switch (toolName) {
    case "Read":
      return checkRead(input, cwd);
    case "Grep":
      return checkGrep(input);
    case "Glob":
      return checkGlob(input);
    case "Bash":
      return checkBash(input, cwd);
    case "Write":
    case "Edit":
    case "MultiEdit":
    case "NotebookEdit":
      return checkWrite(toolName, input);
    default:
      return allow();
  }
}

try {
  main();
} catch (err) {
  // Fail OPEN: never brick the session because of a bug in the guard.
  try {
    fs.writeSync(2, "secret-guard: internal error (fail-open): " + ((err && err.message) || err) + "\n");
  } catch (e) {
    /* ignore */
  }
  process.exit(0);
}
