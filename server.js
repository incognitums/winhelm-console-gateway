#!/usr/bin/env node
// WinHelm Gemini gateway — query-token gate + tool allowlist in front of WinHelm.
// Design constraints:
//   - no OAuth discovery (those paths must 404)
//   - query token is a bearer secret: never printed, never stored in plaintext
//   - bounded, revocable, single-purpose credential
// Local only. Nothing here talks to the internet; exposure is a separate, explicit step.

import http from "node:http";
import { createHash, timingSafeEqual, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { join, resolve } from "node:path";
import os from "node:os";

function getUpstreamAuthToken() {
  if (typeof cfg !== "undefined" && cfg?.upstreamAuthToken && typeof cfg.upstreamAuthToken === "string" && cfg.upstreamAuthToken.trim()) {
    return cfg.upstreamAuthToken.trim();
  }
  const envToken = process.env.WINHELM_AUTH_TOKEN || process.env.MCP_AUTH_TOKEN;
  if (envToken && envToken.trim()) return envToken.trim();
  const tokenFile = join(os.homedir(), ".winhelm", "auth-token");
  if (existsSync(tokenFile)) {
    try {
      const t = readFileSync(tokenFile, "utf8").trim();
      if (t) return t;
    } catch {}
  }
  return null;
}

const DIR = import.meta.dirname;
const configFlag = process.argv.indexOf("--config");
const CONFIG_PATH = configFlag > -1 ? process.argv[configFlag + 1] : join(DIR, "config.json");
const BODY_LIMIT = 8 * 1024 * 1024;
// tools/list from lnwjud measured ~426 KB for 266 tools. 8 MB leaves room to grow
// while still refusing an unbounded buffering path.
const RESPONSE_LIMIT = 8 * 1024 * 1024;
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 240;

const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

function loadConfig() {
  const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  for (const key of ["listenPort", "upstreamUrl", "allowTools", "denyTools"]) {
    if (!(key in cfg)) throw new Error(`config.json missing "${key}"`);
  }
  const oauthEnabled = Boolean(cfg.oauth?.enabled);
  if (oauthEnabled) {
    if (!cfg.oauth.authority) throw new Error("config.json oauth.authority is required when oauth.enabled is true");
    const ids = Array.isArray(cfg.oauth.clientIds) && cfg.oauth.clientIds.length
      ? cfg.oauth.clientIds
      : cfg.oauth.clientId ? [cfg.oauth.clientId] : [];
    if (ids.length === 0) throw new Error("config.json needs oauth.clientIds (or oauth.clientId)");
    if (ids.some((id) => typeof id !== "string" || !id)) throw new Error("config.json oauth.clientIds must be non-empty strings");
    cfg.oauth.clientIds = ids;
    if (!/^https:\/\/[^/]+$/.test(cfg.oauth.authority)) {
      throw new Error("config.json oauth.authority must be https://<host> with no trailing slash");
    }
  }
  if (!("tokenSha256" in cfg)) {
    if (!oauthEnabled) throw new Error('config.json missing "tokenSha256"');
  } else if (!/^[0-9a-f]{64}$/.test(cfg.tokenSha256)) {
    throw new Error('config.json tokenSha256 is not a 64-char lowercase hex digest — run: node server.js --issue-token');
  }
  return cfg;
}

function runPowerShell(command, stdinText) {
  return new Promise((resolve) => {
    const ps = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", command], {
      stdio: [stdinText === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let out = "";
    let err = "";
    ps.stdout.on("data", (d) => { out += d.toString("utf8"); });
    ps.stderr.on("data", (d) => { err += d.toString("utf8"); });
    ps.on("exit", (code) => resolve({ code, out, err }));
    if (stdinText !== undefined) ps.stdin.end(stdinText, "utf8");
  });
}

async function issueToken(reveal) {
  const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  const token = "whlm_" + randomBytes(32).toString("base64url");
  const hash = sha256hex(token);
  const fullUrl = `${cfg.baseUrl}?token=${token}`;

  cfg.tokenSha256 = hash;
  cfg.tokenFingerprint = hash.slice(0, 12);
  cfg.tokenIssuedAt = new Date().toISOString();
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", "utf8");

  // Clipboard only, and only after confirming the write actually landed.
  // A fire-and-forget child loses the value when this process exits.
  const set = await runPowerShell("Set-Clipboard -Value ([Console]::In.ReadToEnd())", fullUrl);
  const readBack = set.code === 0 ? await runPowerShell("Get-Clipboard -Raw") : { out: "" };
  const clipboardOk = readBack.out.trim() === fullUrl;

  console.log("token issued");
  console.log(`fingerprint : ${cfg.tokenFingerprint}`);
  console.log(`baseUrl     : ${cfg.baseUrl}`);
  console.log(`clipboard   : ${clipboardOk ? "verified (full URL is on the clipboard)" : "FAILED — value did not land"}`);

  if (!clipboardOk) {
    console.log("");
    console.log("The clipboard write could not be confirmed. Run this in your own PowerShell window instead,");
    console.log("where the shell stays alive:");
    console.log(`  cd ${DIR}`);
    console.log("  node server.js --issue-token");
    console.log("If it still fails, use --reveal to print the URL here, paste it into Gemini, then clear");
    console.log("this terminal's scrollback. Never paste it into a chat, issue, or log.");
  }

  if (reveal) {
    console.log("");
    console.log("--- REVEALED (paste into Gemini, then clear your scrollback) ---");
    console.log(fullUrl);
    console.log("--- end ---");
  } else {
    console.log("next        : paste the clipboard value into the Gemini custom app field, then run: node server.js");
  }
}


function makeRateLimiter() {
  const hits = new Map();
  return (key) => {
    const now = Date.now();
    const entry = hits.get(key);
    if (!entry || now - entry.start >= RATE_WINDOW_MS) {
      hits.set(key, { start: now, count: 1 });
      if (hits.size > 2048) for (const [k, v] of hits) if (now - v.start >= RATE_WINDOW_MS) hits.delete(k);
      return true;
    }
    entry.count += 1;
    return entry.count <= RATE_MAX;
  };
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > BODY_LIMIT) throw new Error("BODY_TOO_LARGE");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

// Returns the offending {id, name} for a disallowed tools/call, or null.
function findDisallowedCall(buf, cfg) {
  if (!buf.length) return null;
  let parsed;
  try {
    parsed = JSON.parse(buf.toString("utf8"));
  } catch {
    return null; // not JSON-RPC; let upstream judge it
  }
  for (const msg of Array.isArray(parsed) ? parsed : [parsed]) {
    if (!msg || msg.method !== "tools/call") continue;
    const name = msg.params && typeof msg.params.name === "string" ? msg.params.name : "";
    const allowed = name && !cfg.denyTools.includes(name) && cfg.allowTools.includes(name);
    if (!allowed) return { id: msg.id ?? null, name: name || "<missing>" };
  }
  return null;
}

// True when the request body contains a tools/list message. A request that merely
// lists 266 tools is not a security event, but it is a context-cost event: the model
// pays for every tool it can see, even the ones the policy above would refuse to run.
function isToolsListRequest(buf) {
  if (!buf.length) return false;
  let parsed;
  try {
    parsed = JSON.parse(buf.toString("utf8"));
  } catch {
    return false;
  }
  for (const msg of Array.isArray(parsed) ? parsed : [parsed]) {
    if (msg && msg.method === "tools/list") return true;
  }
  return false;
}

function toolAllowed(name, cfg) {
  return typeof name === "string" && name !== "" && cfg.allowTools.includes(name) && !cfg.denyTools.includes(name);
}

// Filter one JSON-RPC object in place. Returns the number of tools removed, or -1
// when the object carried no tools array.
function filterToolObject(obj, cfg) {
  if (!obj || typeof obj !== "object") return -1;
  const result = obj.result;
  if (!result || !Array.isArray(result.tools)) return -1;
  const before = result.tools.length;
  result.tools = result.tools.filter((tool) => toolAllowed(tool && tool.name, cfg));
  return before - result.tools.length;
}

// A JSON-RPC batch is an array of messages. Filtering only single objects would leave a
// batched tools/list unfiltered, which leaks every denied tool name to the client.
function filterToolPayload(value, cfg) {
  if (Array.isArray(value)) {
    let removed = 0;
    for (const msg of value) {
      const delta = filterToolObject(msg, cfg);
      if (delta > 0) removed += delta;
    }
    return removed;
  }
  return filterToolObject(value, cfg);
}

// tools/list arrives as an SSE frame (`event: message` + `data: {...}`), not as a
// plain JSON body. Only the data payload is rewritten; every other line is preserved
// so the frame stays valid SSE for the client.
function filterSseTools(text, cfg) {
  const sep = text.includes("\r\n\r\n") ? "\r\n\r\n" : "\n\n";
  const nl = sep === "\r\n\r\n" ? "\r\n" : "\n";
  let removed = 0;
  const frames = text.split(sep).map((frame) => {
    if (!frame.trim()) return frame;
    const lines = frame.split(nl);
    let first = -1;
    let last = -1;
    const dataLines = [];
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i].startsWith("data:")) continue;
      if (first === -1) first = i;
      last = i;
      dataLines.push(lines[i].slice(5).replace(/^ /, ""));
    }
    if (first === -1) return frame;
    let obj;
    try {
      obj = JSON.parse(dataLines.join("\n"));
    } catch {
      return frame;
    }
    const delta = filterToolPayload(obj, cfg);
    if (delta < 0) return frame;
    removed += delta;
    const rebuilt = lines.slice(0, first).concat([`data: ${JSON.stringify(obj)}`], lines.slice(last + 1));
    return rebuilt.join(nl);
  });
  return { text: frames.join(sep), removed };
}


function forward(req, res, cfg, upstreamPath, body, filterTools = false) {
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    // Drop our own credential, hop-by-hop headers, forwarding headers, cookies, and negotiation we do not need.
    if ([
      "host", "authorization", "cookie", "content-length", "content-encoding",
      "connection", "keep-alive", "transfer-encoding", "accept-encoding",
      "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded",
      "proxy-authorization", "proxy-connection", "te", "trailer", "upgrade",
    ].includes(key)) continue;
    headers[key] = value;
  }
  if (body.length) headers["content-length"] = String(body.length);
  const upstreamToken = getUpstreamAuthToken();
  if (upstreamToken) {
    headers["authorization"] = `Bearer ${upstreamToken}`;
  }

  const passThrough = (upRes) => {
    const out = {};
    for (const [key, value] of Object.entries(upRes.headers)) {
      if (["connection", "keep-alive", "transfer-encoding"].includes(key)) continue;
      out[key] = value;
    }
    return out;
  };

  const upstream = new URL(cfg.upstreamUrl);
  const call = http.request(
    { hostname: upstream.hostname, port: upstream.port, path: upstreamPath, method: req.method, headers },
    (upRes) => {
      if (!filterTools) {
        res.writeHead(upRes.statusCode ?? 502, passThrough(upRes));
        upRes.pipe(res);
        return;
      }

      // Buffered path: only for tools/list, where the whole payload must be rewritten.
      const chunks = [];
      let size = 0;
      upRes.on("data", (chunk) => {
        size += chunk.length;
        if (size > RESPONSE_LIMIT) {
          upRes.destroy();
          if (!res.headersSent) {
            res.writeHead(502, { "content-type": "application/json" });
            res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "UPSTREAM_RESPONSE_TOO_LARGE" }, id: null }));
          }
          return;
        }
        chunks.push(chunk);
      });
      upRes.on("end", () => {
        if (res.headersSent) return;
        const raw = Buffer.concat(chunks).toString("utf8");
        const contentType = String(upRes.headers["content-type"] ?? "");
        let out = raw;
        let removed = 0;
        if (contentType.includes("text/event-stream")) {
          const filtered = filterSseTools(raw, cfg);
          out = filtered.text;
          removed = filtered.removed;
        } else {
          try {
            const obj = JSON.parse(raw);
            const delta = filterToolPayload(obj, cfg);
            if (delta >= 0) {
              out = JSON.stringify(obj);
              removed = delta;
            }
          } catch {
            // Not JSON after all: forward unchanged rather than corrupting the payload.
          }
        }
        if (removed > 0) {
          console.log(`${new Date().toISOString()} tools/list filtered: -${removed} tools (allow=${cfg.allowTools.length} deny=${cfg.denyTools.length})`);
        }
        const payload = Buffer.from(out, "utf8");
        const outHeaders = passThrough(upRes);
        delete outHeaders["content-length"];
        outHeaders["content-length"] = String(payload.length);
        res.writeHead(upRes.statusCode ?? 502, outHeaders);
        res.end(payload);
      });
      upRes.on("error", () => {
        if (!res.headersSent) {
          res.writeHead(502, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "UPSTREAM_UNAVAILABLE" }, id: null }));
        }
      });
    },
  );
  call.setTimeout(30_000, () => call.destroy(new Error("UPSTREAM_TIMEOUT")));
  call.on("error", () => {
    if (!res.headersSent) {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "UPSTREAM_UNAVAILABLE" }, id: null }));
    } else {
      res.end();
    }
  });
  call.end(body.length ? body : undefined);
}

async function main() {
  if (process.argv.includes("--issue-token")) return issueToken(process.argv.includes("--reveal"));

  const cfg = loadConfig();
  const rateOk = makeRateLimiter();
  const oauthEnabled = Boolean(cfg.oauth?.enabled);
  const expected = cfg.tokenSha256 ? Buffer.from(cfg.tokenSha256, "hex") : null;

  const tokenMatches = (candidate) => {
    if (!expected) return false;
    if (typeof candidate !== "string" || !candidate) return false;
    const actual = Buffer.from(sha256hex(candidate), "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  };

  let oauth = null;
  if (oauthEnabled) {
    const { RegistrationStore } = await import("./oauth/r7_store.mjs");
    const { createOAuthLayer } = await import("./oauth-layer.js");
    const storePath = cfg.oauth.storePath
      ? resolve(DIR, cfg.oauth.storePath)
      : join(DIR, "oauth-store.json");
    oauth = createOAuthLayer({
      store: new RegistrationStore({ storePath }),
      authority: cfg.oauth.authority,
      clientIds: cfg.oauth.clientIds,
    });
    console.log(`oauth      : enabled, authority=${cfg.oauth.authority}, clients=${cfg.oauth.clientIds.join(",")}`);
    console.log(`oauth store: ${storePath}`);
  } else {
    console.log("oauth      : disabled (query token only)");
  }

  const clientIpFromReq = (req) => {
    const remote = req.socket.remoteAddress ?? "unknown";
    const isLoopback = remote === "127.0.0.1" || remote === "::1" || remote === "::ffff:127.0.0.1";
    if (isLoopback) {
      const xff = req.headers["x-forwarded-for"];
      const raw = Array.isArray(xff) ? xff[0] : xff;
      if (typeof raw === "string" && raw.trim()) {
        const parts = raw.split(",").map((s) => s.trim()).filter(Boolean);
        if (parts.length) return parts[parts.length - 1];
      }
    }
    return remote;
  };

  const server = http.createServer(async (req, res) => {
    // A single bad request must never take the process down: there is no auto-restart,
    // and this listener is on a public port.
    try {
    const ip = clientIpFromReq(req);
    const url = new URL(req.url ?? "/", "http://gateway.invalid");

    if (url.pathname === "/healthz") {
      // Liveness only. This endpoint sits on the public path, so it must not disclose
      // the upstream URL or whether OAuth is enabled to an unauthenticated caller.
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    // OAuth/discovery routes (and the bootstrap HTML handoff) are handled here when
    // enabled. When disabled they fall through to the 404 below, so the earlier
    // no-OAuth posture is preserved by configuration alone.
    if (oauth && (url.pathname.startsWith("/oauth/") || url.pathname.startsWith("/.well-known/"))) {
      // These routes are unauthenticated, so they must be limited too — otherwise the
      // OAuth surface is an unthrottled way to force store writes and lock contention.
      if (!rateOk(`ip:${ip}`)) {
        res.writeHead(429, { "content-type": "application/json", "retry-after": "60" });
        res.end(JSON.stringify({ error: "rate_limited" }));
        return;
      }
      const startedAt = Date.now();
      res.on("finish", () => {
        console.log(`${new Date().toISOString()} ${ip} ${req.method} ${url.pathname} ${res.statusCode} ${Date.now() - startedAt}ms oauth`);
      });
      if (await oauth.handle(req, res, url)) return;
    }

    const bearer = /^Bearer +(\S+)$/i.exec(req.headers.authorization ?? "");
    const bearerValue = bearer ? bearer[1] : null;

    // Authenticate first, then rate limit by the identity that actually authenticated.
    // Bucketing by IP alone would be useless behind the ingress (every request arrives
    // from 127.0.0.1), so one abusive client would starve the owner. An unauthenticated
    // caller still gets its own IP bucket, which is what stops brute force.
    let authorized = false;
    let authMode = "none";
    if (oauth && bearerValue) {
      const grant = await oauth.authenticateBearer(bearerValue);
      if (grant) {
        authorized = true;
        authMode = "oauth";
      }
    }
    // Query-token mode is opt-in and off by default once OAuth is enabled.
    const allowQuery = oauthEnabled ? cfg.allowQueryToken === true : true;
    if (!authorized && allowQuery) {
      const presented = url.searchParams.get("token") ?? bearerValue;
      if (tokenMatches(presented)) {
        authorized = true;
        authMode = "query-token";
      }
    }

    if (!authorized) {
      // Unauthenticated callers share one IP bucket; the owner's authenticated traffic
      // does not, so an abusive client cannot starve it.
      if (!rateOk(`ip:${ip}`)) {
        res.writeHead(429, { "content-type": "application/json", "retry-after": "60" });
        res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "RATE_LIMITED" }, id: null }));
        return;
      }
      const challenge = oauth
        ? `Bearer realm="winhelm", resource_metadata="${cfg.oauth.authority}/.well-known/oauth-protected-resource"`
        : 'Bearer realm="winhelm"';
      res.writeHead(401, { "content-type": "application/json", "www-authenticate": challenge });
      res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "UNAUTHORIZED" }, id: null }));
      return;
    }
    void authMode;

    // Bucket authenticated traffic by the credential itself.
    const rateKey = authMode === "oauth"
      ? `tok:${sha256hex(bearerValue ?? "")}`
      : `qtok:${sha256hex(cfg.tokenSha256 ?? "")}`;
    if (!rateOk(rateKey)) {
      res.writeHead(429, { "content-type": "application/json", "retry-after": "60" });
      res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "RATE_LIMITED" }, id: null }));
      return;
    }

    if (req.headers["content-encoding"] && req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(415, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32600, message: "UNSUPPORTED_CONTENT_ENCODING" }, id: null }));
      return;
    }

    let body;
    try {
      body = req.method === "GET" || req.method === "HEAD" ? Buffer.alloc(0) : await readBody(req);
    } catch (err) {
      const tooLarge = err.message === "BODY_TOO_LARGE";
      res.writeHead(tooLarge ? 413 : 400, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: err.message }, id: null }));
      return;
    }

    if (req.method === "POST" && body.length > 0) {
      try {
        JSON.parse(body.toString("utf8"));
      } catch {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32700, message: "INVALID_JSON" }, id: null }));
        return;
      }
    }

    const blocked = findDisallowedCall(body, cfg);
    if (blocked) {
      console.log(`${new Date().toISOString()} ${ip} ${req.method} ${url.pathname} 200 tool=${blocked.name} DENIED`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        jsonrpc: "2.0",
        id: blocked.id,
        error: { code: -32001, message: "TOOL_NOT_ALLOWED", data: { tool: blocked.name } },
      }));
      return;
    }

    // Always forward to the configured upstream endpoint, whatever mount path the public
    // origin uses (/lnwjud, /lnwjud/mcp, or /). This removes a whole class of routing bugs.
    const forwarded = new URLSearchParams(url.searchParams);
    for (const key of ["token", "access_token", "auth"]) forwarded.delete(key);
    const query = forwarded.toString();
    const upstreamPath = new URL(cfg.upstreamUrl).pathname + (query ? `?${query}` : "");

    res.on("close", () => {
      console.log(`${new Date().toISOString()} ${ip} ${req.method} ${url.pathname} ${res.statusCode}`);
    });
    forward(req, res, cfg, upstreamPath, body, isToolsListRequest(body));
    } catch (err) {
      console.log(`${new Date().toISOString()} request failed: ${err?.message ?? err}`);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32603, message: "INTERNAL_ERROR" }, id: null }));
      } else {
        res.end();
      }
    }
  });

  server.listen(cfg.listenPort, "127.0.0.1", () => {
    console.log(`WinHelm gateway listening on http://127.0.0.1:${cfg.listenPort}`);
    console.log(`upstream  : ${cfg.upstreamUrl}`);
    console.log(`allowTools: ${cfg.allowTools.length} | denyTools: ${cfg.denyTools.length}`);
    console.log(`fingerprint: ${cfg.tokenFingerprint ?? "unknown"}`);
  });
}

main().catch((err) => {
  console.error(`error: ${err.message}`);
  process.exitCode = 1;
});
