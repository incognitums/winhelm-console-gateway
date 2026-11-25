// Local admin console for the WinHelm gateway.
//
// Why a separate process and a separate port: the gateway's own port is published to the
// internet through the Tailscale funnel. An admin UI must never live there. This listens on
// loopback only and is never wired into the ingress.
//
// Threat model: anything on this machine, and any web page the browser has open, can reach a
// loopback port. So every API call needs a per-start token in a header (never a query string),
// the Host header must be exactly ours (DNS rebinding), and a cross-origin Origin is rejected.
// The token is handed to the browser in the URL fragment, which the server never receives.

import http from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { readFile, writeFile, copyFile, mkdir } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn, execFileSync } from "node:child_process";
import { Socket } from "node:net";

function getUpstreamAuthInfo(cfg = null) {
  if (cfg?.upstreamAuthToken && typeof cfg.upstreamAuthToken === "string" && cfg.upstreamAuthToken.trim()) {
    return { token: cfg.upstreamAuthToken.trim(), source: "config" };
  }
  const envToken = process.env.WINHELM_AUTH_TOKEN || process.env.MCP_AUTH_TOKEN;
  if (envToken && envToken.trim()) return { token: envToken.trim(), source: "env" };
  const tokenFile = path.join(os.homedir(), ".winhelm", "auth-token");
  if (existsSync(tokenFile)) {
    try {
      const t = readFileSync(tokenFile, "utf8").trim();
      if (t) return { token: t, source: "file" };
    } catch {}
  }
  return { token: null, source: "none" };
}

function getUpstreamAuthToken(cfg = null) {
  return getUpstreamAuthInfo(cfg).token;
}

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const CONFIG_PATH = path.join(ROOT, "config.json");
const INGRESS_CONFIG = CONFIG_PATH;
const DEFAULTS_PATH = path.join(HERE, "..", "defaults", "tools.default.json");
const WINHELM_CORE_DIR = path.resolve(ROOT, "..", "winhelm-mcp");

let cachedGlobalNodeModules = null;
function getGlobalNodeModules() {
  if (cachedGlobalNodeModules !== null) return cachedGlobalNodeModules;
  try {
    const npmBin = process.platform === "win32" ? "npm.cmd" : "npm";
    const out = execFileSync(npmBin, ["root", "-g"], {
      encoding: "utf8",
      timeout: 3000,
      windowsHide: true,
    }).trim();
    cachedGlobalNodeModules = out || "";
  } catch {
    cachedGlobalNodeModules = "";
  }
  return cachedGlobalNodeModules;
}

const VALID_CORE_PRESETS = new Set(["safe", "balanced", "power", "minimal", "core", "dev", "sysadmin", "full"]);

async function alwaysAllowToolPolicy(toolName, waitJobId = "") {
  if (!toolName || !/^[A-Za-z0-9._-]+$/.test(toolName)) return false;
  const existing = (await loadWinHelmConfig()) || { schemaVersion: 2, toolPolicy: {} };
  const isTerminal = toolName.startsWith("terminal_") || toolName === "command_run";
  if (isTerminal) {
    existing.terminal = { ...(existing.terminal || {}), mode: "full", approvalTtlSeconds: existing.terminal?.approvalTtlSeconds || 300 };
    existing.allowSystemExecution = true;
  } else {
    existing.toolPolicy = { ...(existing.toolPolicy || {}), [toolName]: "auto" };
  }
  if (!VALID_CORE_PRESETS.has(existing.profilePreset)) {
    existing.profilePreset = existing.terminal?.mode === "full" ? "power" : "balanced";
  }
  await saveWinHelmConfig(existing);

  // Wait until the just-approved job finishes (up to 15s) before restarting Core to reload policy.
  (async () => {
    const jobsFile = path.join(os.homedir(), ".winhelm", "approval-jobs.json");
    const deadline = Date.now() + 15000;
    while (waitJobId && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 1000));
      try {
        if (existsSync(jobsFile)) {
          const jData = JSON.parse(readFileSync(jobsFile, "utf8"));
          const job = (jData.jobs || []).find((j) => j.id === waitJobId);
          if (!job || ["completed", "denied", "failed", "expired", "cancelled"].includes(job.state)) {
            await new Promise((r) => setTimeout(r, 1000));
            break;
          }
        }
      } catch {}
    }
    if (!waitJobId) await new Promise((r) => setTimeout(r, 4000));
    await stopCoreProcess().catch(() => {});
    await startCoreProcess().catch(() => {});
  })();
  return true;
}

function resolveWinHelmCoreFile(...segments) {
  const candidates = [
    path.join(WINHELM_CORE_DIR, ...segments),
    path.join(ROOT, "node_modules", "winhelm-mcp", ...segments),
  ];
  if (process.env.APPDATA) {
    candidates.push(path.join(process.env.APPDATA, "npm", "node_modules", "winhelm-mcp", ...segments));
  }
  const globalRoot = getGlobalNodeModules();
  if (globalRoot) {
    candidates.push(path.join(globalRoot, "winhelm-mcp", ...segments));
  }
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

function resolveWinHelmConfigPath() {
  const candidates = [
    path.join(WINHELM_CORE_DIR, "winhelm.local.json"),
    path.join(os.homedir(), ".winhelm", "winhelm.local.json"),
    path.join(os.homedir(), ".winhelm", "config.json"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return path.join(os.homedir(), ".winhelm", "winhelm.local.json");
}

function getStartupLinkPath() {
  const appData = process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming");
  return path.join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "WinHelm Tray.lnk");
}

async function runWinHelmCli(args) {
  const localEntry = resolveWinHelmCoreFile("dist", "index.js");
  if (localEntry) {
    return runNode([localEntry, ...args]);
  }
  return new Promise((resolve) => {
    const child = spawn("cmd.exe", ["/c", "npx", "-y", "winhelm-mcp", ...args], {
      cwd: ROOT,
      windowsHide: true,
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d.toString("utf8")));
    child.stderr.on("data", (d) => (err += d.toString("utf8")));
    child.on("exit", (code) => resolve({ code: code ?? 1, out, err }));
  });
}

async function getFunnelStatus() {
  return new Promise((resolve) => {
    const child = spawn("tailscale", ["funnel", "status", "--json"], { windowsHide: true });
    let out = "";
    let err = "";
    const timer = setTimeout(() => { try { child.kill(); } catch {} resolve({ available: false, active: false }); }, 3000);
    child.stdout.on("data", (d) => (out += d.toString("utf8")));
    child.stderr.on("data", (d) => (err += d.toString("utf8")));
    child.on("error", () => { clearTimeout(timer); resolve({ available: false, active: false }); });
    child.on("exit", (code) => {
      clearTimeout(timer);
      if (code !== 0) return resolve({ available: true, active: false, detail: err.trim() });
      try {
        const parsed = JSON.parse(out || "{}");
        const hasFunnel = Boolean(parsed?.AllowFunnel && Object.values(parsed.AllowFunnel).some(Boolean));
        resolve({ available: true, active: hasFunnel, raw: parsed });
      } catch {
        resolve({ available: true, active: out.includes("Funnel on") });
      }
    });
  });
}

const CANONICAL_TOOLS = [
  // 1. Terminal & Background Tasks (6)
  { name: "terminal_run", category: "Terminal", risk: "R5", desc: "รันคำสั่ง PowerShell / Terminal แบบรอผล", isDangerous: true },
  { name: "terminal_task_start", category: "Terminal", risk: "R5", desc: "เริ่ม Background Task ยาวๆ", isDangerous: true },
  { name: "terminal_task_list", category: "Terminal", risk: "R0", desc: "ดูรายการ Background Tasks ทั้งหมด", isDangerous: false },
  { name: "terminal_task_logs", category: "Terminal", risk: "R0", desc: "อ่าน Logs ของ Background Task", isDangerous: false },
  { name: "terminal_task_send", category: "Terminal", risk: "R5", desc: "ส่ง Input เข้า Task ที่รันอยู่", isDangerous: true },
  { name: "terminal_task_kill", category: "Terminal", risk: "R5", desc: "ยกเลิกหรือสั่งปิด Task", isDangerous: true },

  // 2. Filesystem & Safe Delete (15)
  { name: "file_read", category: "Filesystem", risk: "R0", desc: "อ่านเนื้อหาไฟล์", isDangerous: false },
  { name: "file_write", category: "Filesystem", risk: "R1", desc: "เขียน/สร้างไฟล์", isDangerous: true },
  { name: "file_edit", category: "Filesystem", risk: "R1", desc: "แก้ไขเนื้อหาไฟล์เฉพาะส่วน", isDangerous: true },
  { name: "file_list", category: "Filesystem", risk: "R0", desc: "ดูรายชื่อไฟล์และโฟลเดอร์", isDangerous: false },
  { name: "file_search", category: "Filesystem", risk: "R0", desc: "ค้นหาไฟล์ตามชื่อหรือแพตเทิร์น", isDangerous: false },
  { name: "file_delete_safe", category: "Filesystem", risk: "R1", desc: "ลบไฟล์อย่างปลอดภัย (ลงถังขยะ)", isDangerous: true },
  { name: "file_move", category: "Filesystem", risk: "R1", desc: "ย้ายหรือเปลี่ยนชื่อไฟล์", isDangerous: false },
  { name: "file_copy", category: "Filesystem", risk: "R1", desc: "คัดลอกไฟล์", isDangerous: false },
  { name: "archive_zip", category: "Filesystem", risk: "R1", desc: "บีบอัดไฟล์เป็น .zip", isDangerous: false },
  { name: "archive_unzip", category: "Filesystem", risk: "R1", desc: "แตกไฟล์ .zip", isDangerous: false },
  { name: "file_tail", category: "Filesystem", risk: "R0", desc: "อ่านบรรทัดท้ายสุดของไฟล์", isDangerous: false },
  { name: "file_hash", category: "Filesystem", risk: "R0", desc: "คำนวณ Checksum/Hash ของไฟล์", isDangerous: false },
  { name: "file_search_ripgrep", category: "Filesystem", risk: "R0", desc: "ค้นหาข้อความในโค้ดด้วย ripgrep ความเร็วสูง", isDangerous: false },
  { name: "pdf_generate", category: "Filesystem", risk: "R1", desc: "แปลงเอกสาร/Markdown เป็น PDF", isDangerous: false },
  { name: "file_preview", category: "Filesystem", risk: "R0", desc: "ดูตัวอย่างภาพหรือไฟล์เอกสาร", isDangerous: false },

  // 3. Desktop, Clipboard & Toast (5)
  { name: "clipboard_get", category: "Desktop", risk: "R3", desc: "อ่านข้อความใน Clipboard", isDangerous: false },
  { name: "clipboard_set", category: "Desktop", risk: "R3", desc: "เขียนข้อความลง Clipboard", isDangerous: false },
  { name: "screen_capture", category: "Desktop", risk: "R3", desc: "จับภาพหน้าจอ Windows", isDangerous: false },
  { name: "system_open", category: "Desktop", risk: "R3", desc: "เปิดไฟล์หรือ URL ด้วยโปรแกรมเริ่มต้น", isDangerous: false },
  { name: "notification_send", category: "Desktop", risk: "R1", desc: "ส่งแจ้งเตือน Windows Toast Notification", isDangerous: false },

  // 4. System, Processes & Services (9)
  { name: "system_info", category: "System", risk: "R0", desc: "ดูข้อมูลฮาร์ดแวร์และ OS", isDangerous: false },
  { name: "gpu_info", category: "System", risk: "R0", desc: "ดูข้อมูล GPU และ VRAM", isDangerous: false },
  { name: "process_list", category: "System", risk: "R0", desc: "ดูรายการโปรเซสที่กำลังทำงาน", isDangerous: false },
  { name: "process_kill", category: "System", risk: "R4", desc: "สั่งปิด/ฆ่าโปรเซส", isDangerous: true },
  { name: "port_check", category: "System", risk: "R0", desc: "ตรวจสอบสถานะพอร์ตเครือข่าย", isDangerous: false },
  { name: "eventlog_query", category: "System", risk: "R0", desc: "สืบค้น Windows Event Logs", isDangerous: false },
  { name: "service_list", category: "System", risk: "R0", desc: "ดูรายการ Windows Services", isDangerous: false },
  { name: "service_status", category: "System", risk: "R0", desc: "ดูสถานะ Windows Service", isDangerous: false },
  { name: "service_control", category: "System", risk: "R4", desc: "สั่ง Start/Stop Windows Service", isDangerous: true },

  // 5. Network & Probe (3)
  { name: "http_ping", category: "Network", risk: "R2", desc: "ยิง Ping ตรวจสอบเวลาตอบสนอง HTTP", isDangerous: false },
  { name: "http_request", category: "Network", risk: "R2", desc: "ส่งคำขอ HTTP Request (GET/POST)", isDangerous: false },
  { name: "network_info", category: "Network", risk: "R0", desc: "ดูข้อมูล IP, Interfaces และ Tailscale", isDangerous: false },

  // 6. Schema v2 Core & Governance (3)
  { name: "winhelm_status", category: "Governance", risk: "R0", desc: "รายงานสถานะ WinHelm Server, Policy และ Schema Mode", isDangerous: false },
  { name: "winhelm_job_status", category: "Governance", risk: "R0", desc: "ตรวจสอบสถานะการขออนุมัติคำสั่ง (Job Approval)", isDangerous: false },
  { name: "command_run", category: "Governance", risk: "R5", desc: "รันคำสั่งภายใต้การควบคุม Policy Schema v2", isDangerous: true },

  // 7. Spec 3.4 Tier A Integrity & Projections (9)
  { name: "file_inspect_batch", category: "Integrity", risk: "R0", desc: "ตรวจสอบคุณสมบัติไฟล์หลายรายการพร้อมกัน", isDangerous: false },
  { name: "file_write_atomic", category: "Integrity", risk: "R1", desc: "เขียนไฟล์แบบ Atomic ป้องกันข้อมูลเสียหาย", isDangerous: true },
  { name: "file_create_exclusive", category: "Integrity", risk: "R1", desc: "สร้างไฟล์แบบ Exclusive (ล้มเหลวหากมีอยู่แล้ว)", isDangerous: true },
  { name: "session_current", category: "Governance", risk: "R0", desc: "ดูข้อมูล Session และสิทธิ์ปัจจุบัน", isDangerous: false },
  { name: "session_audit_search", category: "Governance", risk: "R0", desc: "สืบค้นประวัติ Audit Logs ของคำสั่ง", isDangerous: false },
  { name: "file_provenance_lookup", category: "Integrity", risk: "R0", desc: "ตรวจสอบประวัติและแหล่งที่มาของไฟล์", isDangerous: false },
  { name: "command_wait", category: "Terminal", risk: "R0", desc: "รอผลลัพธ์คำสั่งแบบ Asynchronous", isDangerous: false },
  { name: "file_compare", category: "Integrity", risk: "R0", desc: "เปรียบเทียบความแตกต่างของไฟล์ (Diff)", isDangerous: false },
  { name: "directory_manifest", category: "Integrity", risk: "R0", desc: "สร้าง Manifest ตรวจสอบโครงสร้างโฟลเดอร์", isDangerous: false },

  // 8. Spec 3.4 Tier B Structured Git & Resource (6)
  { name: "json_parse_strict", category: "Analysis", risk: "R0", desc: "วิเคราะห์ JSON แบบ Strict ตามข้อกำหนด", isDangerous: false },
  { name: "json_canonical_hash", category: "Analysis", risk: "R0", desc: "คำนวณ Canonical Hash ของ JSON", isDangerous: false },
  { name: "memory_info", category: "System", risk: "R0", desc: "ดูข้อมูลการใช้งาน RAM อย่างละเอียด", isDangerous: false },
  { name: "process_resource_monitor", category: "System", risk: "R0", desc: "มอนิเตอร์ CPU/RAM ของ Process ต่อเนื่อง", isDangerous: false },
  { name: "git_status_structured", category: "Git", risk: "R0", desc: "อ่านสถานะ Git Repository แบบ JSON โครงสร้างชัดเจน", isDangerous: false },
  { name: "git_diff_structured", category: "Git", risk: "R0", desc: "ดู Git Diff แบบ Structured JSON", isDangerous: false },
];

async function loadWinHelmConfig() {
  const cfgPath = resolveWinHelmConfigPath();
  if (!existsSync(cfgPath)) return null;
  try {
    return JSON.parse(await readFile(cfgPath, "utf8"));
  } catch {
    return null;
  }
}

async function saveWinHelmConfig(config) {
  const cfgPath = resolveWinHelmConfigPath();
  const cfgDir = path.dirname(cfgPath);
  const backupDir = path.join(cfgDir, "config-backups");
  await mkdir(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  if (existsSync(cfgPath)) {
    await copyFile(cfgPath, path.join(backupDir, `winhelm.local-${stamp}.json`));
  }
  await writeFile(cfgPath, JSON.stringify(config, null, 2) + "\n", "utf8");
  return { backup: `config-backups/winhelm.local-${stamp}.json`, path: cfgPath };
}

async function saveConfigUpstreamToken(token) {
  const cfg = await loadConfig();
  if (token && typeof token === "string" && token.trim()) {
    cfg.upstreamAuthToken = token.trim();
  } else {
    delete cfg.upstreamAuthToken;
  }
  const backupDir = path.join(ROOT, "config-backups");
  await mkdir(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  await copyFile(CONFIG_PATH, path.join(backupDir, `config-${stamp}.json`));
  await writeFile(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", "utf8");
  return { backup: `config-backups/config-${stamp}.json` };
}

let initialConfig = {};
try {
  initialConfig = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
} catch {}

const PORT = Number(process.env.ADMIN_PORT ?? initialConfig.adminPort ?? 18789);
const HOST = "127.0.0.1";
// The tray passes its own token so it can open the page without parsing stdout. A token
// from the environment must still be long enough to be unguessable.
const ENV_TOKEN = process.env.ADMIN_TOKEN;
const TOKEN = typeof ENV_TOKEN === "string" && ENV_TOKEN.length >= 32
  ? ENV_TOKEN
  : randomBytes(32).toString("base64url");
const MAX_BODY = 2 * 1024 * 1024;
const COOKIE_NAME = "admin_token";
// A one-time launch ticket keeps the long-lived token out of the browser's command line.
// The app-window URL carries the ticket; the page is then authenticated by a Strict cookie.
// The launcher generates the ticket and passes it through the environment, so neither the
// ticket nor the token is ever written to a command line or to this process's log file.
const ENV_LAUNCH_TICKET = process.env.ADMIN_LAUNCH_TICKET;
const LAUNCH_TICKET = typeof ENV_LAUNCH_TICKET === "string" && ENV_LAUNCH_TICKET.length >= 24
  ? ENV_LAUNCH_TICKET
  : randomBytes(24).toString("base64url");
let launchTicketUsed = false;
const LAUNCH_TICKET_TTL_MS = 5 * 60 * 1000;
const launchTicketIssuedAt = Date.now();

const DANGEROUS = new Set([
  "terminal_run", "terminal_task_start", "terminal_task_kill", "process_kill",
  "file_delete_safe", "service_control", "file_write", "file_edit", "shell", "computer_use",
]);

const OAUTH_SETUP = path.join(ROOT, "oauth-setup.mjs");
const LEGACY_SECRET = path.join(ROOT, "gemini-client-secret.dpapi");
const secretFileFor = (id) => path.join(ROOT, `client-secret-${String(id).replace(/[^A-Za-z0-9._-]/g, "_")}.dpapi`);
const secretExists = (id, singleClient) =>
  existsSync(secretFileFor(id)) || (singleClient && existsSync(LEGACY_SECRET));
// Shape-valid placeholder: a brand new install cannot know Gemini's real callback id,
// and adoption adds the real one on the first authorize.
const PLACEHOLDER_REDIRECT = "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-000000000000000000000000";

// ------------------------------------------------------------------ helpers

const sha256 = (s) => {
  // local import to keep the top clean
  return cryptoHash(s);
};
let cryptoHash = () => { throw new Error("uninitialised"); };
const { createHash } = await import("node:crypto");
cryptoHash = (s) => createHash("sha256").update(s, "utf8").digest("hex");

function send(res, status, body, type = "application/json") {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  res.writeHead(status, {
    "content-type": type,
    "content-length": String(buf.length),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(buf);
}

const json = (res, status, obj) => send(res, status, JSON.stringify(obj), "application/json");

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function cookieToken(req) {
  const raw = req.headers.cookie;
  if (typeof raw !== "string") return null;
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 1) continue;
    if (part.slice(0, i).trim() === COOKIE_NAME) return part.slice(i + 1).trim();
  }
  return null;
}

function tokenOk(req) {
  const header = req.headers["x-admin-token"];
  if (safeEqual(header, TOKEN)) return true;
  // Cookie auth exists so an app window can be opened without a token in its command line.
  // SameSite=Strict plus the Origin/Host checks below are what keep this from being CSRF-able.
  return safeEqual(cookieToken(req), TOKEN);
}

function hostOk(req) {
  const host = String(req.headers.host ?? "");
  return host === `${HOST}:${PORT}`;
}

function originOk(req) {
  const origin = req.headers.origin;
  if (origin === undefined) return true; // same-origin fetches from our page send Origin; curl does not
  return origin === `http://${HOST}:${PORT}`;
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw Object.assign(new Error("body too large"), { status: 413 });
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw Object.assign(new Error("invalid JSON"), { status: 400 });
  }
}

// ------------------------------------------------------------- upstream inventory

async function fetchInventory(upstreamUrl, cfg = null) {
  const base = new URL(upstreamUrl);
  const origin = `${base.protocol}//${base.host}`;
  const config = cfg || (await loadConfig().catch(() => ({})));
  const authToken = getUpstreamAuthToken(config);
  const headers = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...(authToken ? { authorization: `Bearer ${authToken}` } : {}),
  };

  const initRes = await fetch(`${origin}${base.pathname}`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "winhelm-admin", version: "1" } },
    }),
    signal: AbortSignal.timeout(4000),
  });
  if (!initRes.ok) throw new Error(`initialize failed: ${initRes.status}`);
  const sessionId = initRes.headers.get("mcp-session-id") ?? "";
  await initRes.text();

  const sessionHeaders = { ...headers, ...(sessionId ? { "mcp-session-id": sessionId } : {}) };
  await fetch(`${origin}${base.pathname}`, {
    method: "POST", headers: sessionHeaders,
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    signal: AbortSignal.timeout(4000),
  }).catch(() => {});

  const listRes = await fetch(`${origin}${base.pathname}`, {
    method: "POST", headers: sessionHeaders,
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
    signal: AbortSignal.timeout(30000),
  });
  if (!listRes.ok) throw new Error(`tools/list failed: ${listRes.status}`);
  const text = await listRes.text();

  const payloadLine = text
    .split(/\r?\n/)
    .find((line) => line.startsWith("data:"));
  const payload = payloadLine ? payloadLine.slice(5).trim() : text;
  const parsed = JSON.parse(payload);
  if (!parsed?.result?.tools) throw new Error("tools/list response had no result.tools");
  return parsed.result.tools;
}

// ------------------------------------------------------------------- config io

async function loadConfig() {
  const raw = await readFile(CONFIG_PATH, "utf8");
  return JSON.parse(raw);
}

async function saveConfigAllowing(allowTools, denyTools, extra = null) {
  const cfg = await loadConfig();
  const before = JSON.stringify({ a: cfg.allowTools, d: cfg.denyTools, m: cfg.approvalUiMode });
  cfg.allowTools = allowTools;
  cfg.denyTools = denyTools;
  if (extra && (extra.approvalUiMode === "tray_dialog" || extra.approvalUiMode === "console_only")) {
    cfg.approvalUiMode = extra.approvalUiMode;
  }
  const after = JSON.stringify({ a: cfg.allowTools, d: cfg.denyTools, m: cfg.approvalUiMode });

  const backupDir = path.join(ROOT, "config-backups");
  await mkdir(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  await copyFile(CONFIG_PATH, path.join(backupDir, `config-${stamp}.json`));

  await writeFile(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", "utf8");
  return { changed: before !== after, backup: `config-backups/config-${stamp}.json` };
}

async function saveConfigUpstream(upstreamUrl) {
  const cfg = await loadConfig();
  const before = cfg.upstreamUrl;
  cfg.upstreamUrl = upstreamUrl;
  const after = cfg.upstreamUrl;

  const backupDir = path.join(ROOT, "config-backups");
  await mkdir(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  await copyFile(CONFIG_PATH, path.join(backupDir, `config-${stamp}.json`));

  await writeFile(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", "utf8");
  return { changed: before !== after, backup: `config-backups/config-${stamp}.json` };
}

async function detectWinHelmUpstream() {
  const ports = await new Promise((resolve) => {
    const cmd = `$p = (Get-Process -Name 'node','winhelm','winhelm-mcp' -ErrorAction SilentlyContinue).Id; if ($p) { (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -in $p }).LocalPort | Select-Object -Unique }`;
    const child = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", cmd], { windowsHide: true });
    let out = "";
    child.stdout.on("data", (d) => (out += d.toString("utf8")));
    child.on("exit", () => {
      const list = out.split(/\r?\n/).map((s) => s.trim()).filter((s) => /^\d+$/.test(s)).map(Number);
      const candidates = [...new Set([...list, 18790, 18791, 49672, 3000])];
      resolve(candidates);
    });
    child.on("error", () => resolve([18790, 18791, 49672]));
  });

  for (const port of ports) {
    const candidate = `http://127.0.0.1:${port}/mcp`;
    try {
      const tools = await fetchInventory(candidate);
      if (Array.isArray(tools) && tools.length > 0) {
        return { ok: true, port, url: candidate, toolCount: tools.length };
      }
    } catch {
      // not responding or not an MCP endpoint
    }
  }

  return { ok: false, error: "ไม่พบพอร์ตของ WinHelm ที่เปิดตอบสนอง MCP tools/list", foundPorts: ports };
}

function asStringArray(arr) {
  if (!Array.isArray(arr)) return [];
  return [...new Set(arr.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim()))];
}

function toolBytes(tool) {
  return Buffer.byteLength(JSON.stringify(tool), "utf8");
}

// --------------------------------------------------------------- setup / onboarding

function runNode(args) {
  return new Promise((resolve) => {
    const child = spawn("node", args, { cwd: ROOT, windowsHide: true });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d.toString("utf8")));
    child.stderr.on("data", (d) => (err += d.toString("utf8")));
    child.on("exit", (code) => resolve({ code, out, err }));
  });
}

async function portListening(port) {
  return new Promise((resolve) => {
    const socket = new Socket();
    socket.setTimeout(700);
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("timeout", () => { socket.destroy(); resolve(false); });
    socket.once("error", () => resolve(false));
    socket.connect(port, "127.0.0.1");
  });
}

function copyText(value) {
  return new Promise((resolve) => {
    const child = spawn("pwsh.exe", ["-NoProfile", "-NonInteractive", "-Command",
      "$ErrorActionPreference='Stop'; $v=[Console]::In.ReadToEnd(); Set-Clipboard -Value $v; if ((Get-Clipboard -Raw).TrimEnd(\"`r\",\"`n\") -ceq $v) {'MATCH'} else {'MISMATCH'}"],
      { windowsHide: true });
    let out = "";
    child.stdout.on("data", (d) => (out += d.toString("utf8")));
    child.on("exit", () => resolve({ ok: out.includes("MATCH"), detail: out.includes("MATCH") ? "verified" : "clipboard did not keep the value" }));
    child.stdin.end(String(value), "utf8");
  });
}

function detectTailscaleDomain() {
  return new Promise((resolve) => {
    const child = spawn("tailscale", ["status", "--json"], { windowsHide: true });
    let out = "";
    child.stdout.on("data", (d) => (out += d.toString("utf8")));
    child.on("error", () => resolve(null));
    child.on("exit", (code) => {
      if (code !== 0) return resolve(null);
      try {
        const j = JSON.parse(out);
        const dns = j?.Self?.DNSName;
        if (dns) return resolve(dns.replace(/\.$/, ""));
      } catch {}
      resolve(null);
    });
  });
}

async function buildSetup() {
  const cfg = await loadConfig();
  const storePath = path.resolve(ROOT, String(cfg.oauth?.storePath ?? "oauth-store.json"));
  let store = null;
  try {
    store = JSON.parse(await readFile(storePath, "utf8"));
  } catch {
    store = null;
  }

  const allClients = (store?.staticOAuthClients ?? []).filter((c) => c.status === "active");
  const admitted = Array.isArray(cfg.oauth?.clientIds) && cfg.oauth.clientIds.length
    ? cfg.oauth.clientIds
    : cfg.oauth?.clientId ? [cfg.oauth.clientId] : [];

  const activeClientId = cfg.oauth?.clientId ?? (allClients[0]?.client_id ?? null);
  const activeClient = allClients.find((c) => c.client_id === activeClientId) ?? allClients[0] ?? null;

  const clients = allClients.map((c) => ({
    client_id: c.client_id,
    active: c.client_id === (activeClient?.client_id ?? null),
    admitted: admitted.includes(c.client_id),
    redirects: (c.redirect_uris ?? []).length,
    secretAvailable: secretExists(c.client_id, allClients.length === 1),
    activeGrants: (store?.oauthGrants ?? []).filter((g) => g.client_id === c.client_id && g.status === "active").length,
  }));
  const client = activeClient;

  const activeGrantBindings = new Set(
    (store?.oauthGrants ?? []).filter((g) => g.status === "active").map((g) => g.binding_id),
  );

  let invites = (store?.registrationInvites ?? [])
    .filter((i) => i.status === "active")
    .map((i) => {
      const myBindings = (store?.installationBindings ?? []).filter((b) => b.registration_invite_id === i.registration_invite_id);
      const activeGrants = myBindings.filter((b) => activeGrantBindings.has(b.binding_id)).length;
      const reserved = i.registrations_reserved ?? 0;
      const consumed = Math.max(i.quota_epoch_used, activeGrants);
      const pendingReserved = Math.max(0, reserved - activeGrants);
      const totalClaimed = consumed + pendingReserved;
      return {
        alias: i.alias_name,
        used: consumed,
        max: i.quota_epoch_max,
        reserved: pendingReserved,
        activeGrants,
        hasDpapi: existsSync(path.join(ROOT, `invite-${i.alias_name}.dpapi`)),
        exhausted: i.quota_epoch_max !== null && totalClaimed >= i.quota_epoch_max,
      };
    })
    .sort((a, b) => Number(a.exhausted) - Number(b.exhausted));

  const usableInvite = invites.find((i) => !i.exhausted && i.hasDpapi) ?? null;
  const gatewayUp = await portListening(Number(cfg.listenPort));
  const publicPort = cfg.publicPort ? Number(cfg.publicPort) : 443;
  const publicUp = await portListening(publicPort);

  let upstreamOk = false;
  try {
    await fetchInventory(cfg.upstreamUrl, cfg);
    upstreamOk = true;
  } catch {
    upstreamOk = false;
  }

  const tokenInfo = getUpstreamAuthInfo(cfg);
  const tokenMasked = tokenInfo.token
    ? (tokenInfo.token.length > 8 ? `••••••••${tokenInfo.token.slice(-4)}` : "••••••••")
    : null;

  const checks = [
    { id: "client", ok: Boolean(client), label: "มี static client ในระบบ", hint: client ? client.client_id : "ยังไม่มี — กด \"สร้าง client\"" },
    { id: "secret", ok: clients.length > 0 && clients.every((c) => c.secretAvailable), label: "client secret เก็บใน DPAPI", hint: clients.length ? clients.map((c) => `${c.client_id}:${c.secretAvailable ? "ok" : "missing"}`).join(", ") : "ไม่มี client" },
    { id: "redirect", ok: (client?.redirect_uris ?? []).length > 0, label: "มี redirect URI ที่รับไว้", hint: `${(client?.redirect_uris ?? []).length} รายการ (Gemini จะเพิ่มเองเมื่อเชื่อมครั้งแรก)` },
    { id: "invite", ok: Boolean(usableInvite), label: "มี invite ที่ยังใช้ได้", hint: usableInvite ? `${usableInvite.alias} (พร้อมใช้งาน)` : (invites.some((i) => i.reserved > 0) ? "ติดจองค้าง — แนะนำให้กดสร้างใหม่" : "ไม่มี — สร้าง invite ใหม่") },
    { id: "upstreamToken", ok: Boolean(tokenInfo.token), label: "WinHelm Bearer Token", hint: tokenInfo.token ? `พร้อมใช้งาน (${tokenInfo.source === "config" ? "ระบุใน config" : tokenInfo.source === "file" ? "~/.winhelm/auth-token" : "env"})` : "ไม่พบ Token — กดซิงค์หรือกรอก Token" },
    { id: "upstream", ok: upstreamOk, label: "WinHelm ตอบ tools/list", hint: upstreamOk ? "ok" : `ติดต่อ ${cfg.upstreamUrl} ไม่ได้` },
    { id: "gateway", ok: gatewayUp, label: "gateway กำลังทำงาน", hint: `port ${cfg.listenPort}` },
    { id: "public", ok: publicUp || Boolean(cfg.oauth?.authority), label: "public endpoint พร้อม", hint: publicUp ? "เปิด (443)" : "เชื่อมต่อผ่าน Funnel / Ingress" },
  ];

  return {
    serverUrl: cfg.baseUrl || (cfg.oauth?.authority ? `${cfg.oauth.authority}/mcp` : ""),
    clientId: client?.client_id ?? null,
    clientIds: admitted,
    clients,
    clientSecretAvailable: Boolean(client) && secretExists(client.client_id, allClients.length === 1),
    redirectUris: client?.redirect_uris ?? [],
    invites,
    usableInviteAlias: usableInvite?.alias ?? null,
    hasUpstreamToken: Boolean(tokenInfo.token),
    upstreamTokenSource: tokenInfo.source,
    upstreamTokenMasked: tokenMasked,
    checks,
    ready: checks.every((c) => c.ok),
    upstreamUrl: cfg.upstreamUrl,
    configPath: CONFIG_PATH,
  };
}

// -------------------------------------------------------------------- routing

async function handleApi(req, res, url) {
  if (!tokenOk(req)) return json(res, 401, { error: "missing or bad admin token" });

  if (req.method === "GET" && url.pathname === "/api/state") {
    const cfg = await loadConfig();
    let tools = [];
    let inventoryError = null;
    try {
      tools = await fetchInventory(cfg.upstreamUrl);
    } catch (err) {
      inventoryError = String(err?.message ?? err);
    }

    const allow = new Set(cfg.allowTools ?? []);
    const deny = new Set(cfg.denyTools ?? []);
    const items = tools.map((t) => {
      const name = t.name;
      const state = deny.has(name) ? "deny" : allow.has(name) ? "allow" : "default";
      return { name, state, bytes: toolBytes(t), description: String(t.description ?? "").slice(0, 240) };
    });

    const allowedNow = items.filter((t) => t.state === "allow");

    let defaults = null;
    try {
      const def = JSON.parse(await readFile(DEFAULTS_PATH, "utf8"));
      defaults = { allow: (def.allowTools ?? []).length, deny: (def.denyTools ?? []).length };
    } catch {
      defaults = null;
    }

    return json(res, 200, {
      defaults,
      configPath: CONFIG_PATH,
      upstreamUrl: cfg.upstreamUrl,
      counts: {
        live: items.length,
        allow: (cfg.allowTools ?? []).length,
        deny: (cfg.denyTools ?? []).length,
        published: allowedNow.length,
        publishedBytes: allowedNow.reduce((n, t) => n + t.bytes, 0),
        liveBytes: items.reduce((n, t) => n + t.bytes, 0),
      },
      orphanAllow: (cfg.allowTools ?? []).filter((n) => !items.some((t) => t.name === n)),
      orphanDeny: (cfg.denyTools ?? []).filter((n) => !items.some((t) => t.name === n)),
      dangerousAllowed: allowedNow.map((t) => t.name).filter((n) => DANGEROUS.has(n)),
      inventoryError,
      tools: items,
    });
  }

  if (req.method === "POST" && url.pathname === "/api/tools") {
    const body = await readJsonBody(req);
    const { allow = [], deny = [], force = false } = body ?? {};
    if (!Array.isArray(allow) || !Array.isArray(deny)) {
      return json(res, 400, { error: "allow and deny must be arrays" });
    }
    const asStrings = (arr) => [...new Set(arr.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim()))];

    let allowList = asStrings(allow);
    const denyList = asStrings(deny);

    const overlap = allowList.filter((n) => denyList.includes(n));
    if (overlap.length) return json(res, 400, { error: "a tool cannot be both allowed and denied", overlap });

    const dangerous = allowList.filter((n) => DANGEROUS.has(n));
    if (dangerous.length && !force) {
      return json(res, 409, { error: "refusing to allow dangerous tools without explicit confirmation", dangerous });
    }
    if (force && dangerous.length) {
      // keep the deny list authoritative: remove them from deny so the intent is unambiguous
      for (const d of dangerous) {
        const i = denyList.indexOf(d);
        if (i > -1) denyList.splice(i, 1);
      }
    }

    const saved = await saveConfigAllowing(allowList, denyList);
    return json(res, 200, {
      ok: true,
      ...saved,
      counts: { allow: allowList.length, deny: denyList.length },
      restartRequired: saved.changed,
    });
  }

  if (req.method === "GET" && url.pathname === "/api/setup") {
    return json(res, 200, await buildSetup());
  }

  if (req.method === "POST" && url.pathname === "/api/copy") {
    const body = await readJsonBody(req);
    const what = String(body?.what ?? "");
    let args = null;
    if (what === "secret") {
      const setup = await buildSetup();
      const id = String(body?.clientId ?? setup.clientId ?? "");
      if (!id) return json(res, 409, { error: "no client id yet" });
      const entry = setup.clients.find((c) => c.client_id === id);
      if (!entry?.secretAvailable) return json(res, 409, { error: `no stored secret for ${id}` });
      args = [OAUTH_SETUP, "--copy-secret", "--client-id", id];
    } else if (what === "client-id") {
      const setup = await buildSetup();
      const id = String(body?.clientId ?? setup.clientId ?? "");
      if (!id) return json(res, 409, { error: "no client id yet" });
      const clip = await copyText(id);
      return json(res, 200, { ok: clip.ok, what, clientId: id, clipboard: clip.detail });
    } else if (what === "invite") {
      const alias = body?.alias ?? (await buildSetup()).usableInviteAlias;
      if (!alias) return json(res, 409, { error: "no usable invite" });
      args = [OAUTH_SETUP, "--copy-invite", String(alias)];
    } else if (what === "server-url") {
      const setup = await buildSetup();
      const clip = await copyText(setup.serverUrl);
      return json(res, 200, { ok: clip.ok, what, clipboard: clip.detail });
    } else {
      return json(res, 400, { error: "unknown copy target" });
    }
    const run = await runNode(args);
    if (run.code !== 0) return json(res, 500, { error: "copy helper failed", detail: run.err.trim().slice(0, 300) });
    // The helper prints pretty-printed JSON, so parse the whole stream and fall back to the
    // last non-empty line only if that fails.
    const raw = run.out.trim();
    let parsed = null;
    try { parsed = JSON.parse(raw); } catch {
      try { parsed = JSON.parse(raw.split(/\r?\n/).filter(Boolean).pop()); } catch { parsed = null; }
    }
    return json(res, 200, { ok: parsed?.clipboard === "verified" || Boolean(parsed?.ok), what, clipboard: parsed?.clipboard ?? null, helper: parsed });
  }

  if (req.method === "POST" && url.pathname === "/api/init-client") {
    const body = await readJsonBody(req);
    const cfg = await loadConfig();
    const rotate = body?.rotate === true;
    const customClientId = String(body?.clientId ?? "").trim();
    const clientId = customClientId || cfg.oauth?.clientId || "winhelm-gemini-01";

    const args = rotate
      ? [OAUTH_SETUP, "--reset-client", "--redirect-uri", PLACEHOLDER_REDIRECT, "--client-id", clientId]
      : [OAUTH_SETUP, "--init-client", "--redirect-uri", PLACEHOLDER_REDIRECT, "--client-id", clientId];
    const run = await runNode(args);
    if (run.code !== 0) return json(res, 500, { error: "client setup failed", detail: run.err.trim().slice(0, 400) });
    let parsed = null;
    try { parsed = JSON.parse(run.out.trim()); } catch { parsed = null; }

    // Make this client the active one in config.json
    cfg.oauth = cfg.oauth || {};
    cfg.oauth.clientId = clientId;
    if (!Array.isArray(cfg.oauth.clientIds)) cfg.oauth.clientIds = [];
    if (!cfg.oauth.clientIds.includes(clientId)) {
      cfg.oauth.clientIds.push(clientId);
    }
    await writeFile(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", "utf8");
    const gwRestart = await restartGateway();

    return json(res, 200, {
      ok: Boolean(parsed?.client_id),
      clientId: parsed?.client_id ?? clientId,
      rotated: rotate,
      clipboard: parsed?.clipboard ?? null,
      gwRestart,
      note: "paste the clipboard secret into Gemini now; the real redirect URI is adopted on first connect",
    });
  }

  if (req.method === "POST" && url.pathname === "/api/select-client") {
    const body = await readJsonBody(req);
    const targetId = String(body?.clientId ?? "").trim();
    if (!targetId) return json(res, 400, { error: "clientId is required" });
    const cfg = await loadConfig();
    cfg.oauth = cfg.oauth || {};
    cfg.oauth.clientId = targetId;
    if (!Array.isArray(cfg.oauth.clientIds)) cfg.oauth.clientIds = [];
    if (!cfg.oauth.clientIds.includes(targetId)) cfg.oauth.clientIds.push(targetId);
    await writeFile(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", "utf8");
    await restartGateway();
    return json(res, 200, { ok: true, clientId: targetId });
  }

  if (req.method === "POST" && url.pathname === "/api/remove-client") {
    const body = await readJsonBody(req);
    const targetId = String(body?.clientId ?? "").trim();
    if (!targetId) return json(res, 400, { error: "clientId is required" });
    const run = await runNode([OAUTH_SETUP, "--remove-client", targetId]);
    if (run.code !== 0) return json(res, 500, { error: "remove client failed", detail: run.err.trim().slice(0, 400) });
    const cfg = await loadConfig();
    if (cfg.oauth?.clientIds) {
      cfg.oauth.clientIds = cfg.oauth.clientIds.filter((id) => id !== targetId);
    }
    if (cfg.oauth?.clientId === targetId) {
      cfg.oauth.clientId = cfg.oauth.clientIds?.[0] ?? null;
    }
    await writeFile(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", "utf8");
    await restartGateway();
    return json(res, 200, { ok: true, removed: targetId });
  }

  if (req.method === "POST" && url.pathname === "/api/sync-domain") {
    const body = await readJsonBody(req);
    let domain = "";
    if (body?.customUrl) {
      try {
        const u = new URL(body.customUrl);
        domain = u.hostname;
      } catch {
        domain = String(body.customUrl).replace(/^https?:\/\//i, "").split("/")[0].trim();
      }
    } else {
      domain = await detectTailscaleDomain();
    }
    if (!domain) return json(res, 400, { error: "could not detect or parse domain from Tailscale" });

    const cfg = await loadConfig();
    const authority = `https://${domain}`;
    const baseUrl = `https://${domain}/mcp`;
    cfg.baseUrl = baseUrl;
    cfg.oauth = cfg.oauth || {};
    cfg.oauth.authority = authority;
    await writeFile(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", "utf8");
    return json(res, 200, { ok: true, domain, authority, baseUrl });
  }

  if (req.method === "GET" && url.pathname === "/api/invites") {
    const run = await runNode([OAUTH_SETUP, "--list-invites"]);
    if (run.code !== 0) return json(res, 500, { error: "failed to list invites", detail: run.err.trim().slice(0, 400) });
    let invites = [];
    try { invites = JSON.parse(run.out.trim()); } catch { invites = []; }
    return json(res, 200, { ok: true, invites });
  }

  if (req.method === "POST" && url.pathname === "/api/invite") {
    const body = await readJsonBody(req);
    const alias = String(body?.alias ?? "").trim();
    if (!/^[A-Za-z0-9._-]{3,64}$/.test(alias)) return json(res, 400, { error: "alias must be 3-64 chars of A-Z a-z 0-9 . _ -" });
    const quota = body?.quota && Number.isInteger(Number(body.quota)) && Number(body.quota) > 0 ? Number(body.quota) : 1;
    const run = await runNode([OAUTH_SETUP, "--invite", alias, "--quota", String(quota)]);
    if (run.code !== 0) return json(res, 500, { error: "invite creation failed", detail: run.err.trim().slice(0, 400) });
    let parsed = null;
    try { parsed = JSON.parse(run.out.trim()); } catch { parsed = null; }
    return json(res, 200, { ok: Boolean(parsed?.alias), alias: parsed?.alias ?? alias, clipboard: parsed?.clipboard ?? null, quota: parsed?.quota });
  }

  if (req.method === "POST" && url.pathname === "/api/invite/revoke") {
    const body = await readJsonBody(req);
    const alias = String(body?.alias ?? "").trim();
    if (!alias) return json(res, 400, { error: "alias is required" });
    const run = await runNode([OAUTH_SETUP, "--revoke-invite", alias]);
    if (run.code !== 0) return json(res, 500, { error: "failed to revoke invite", detail: run.err.trim().slice(0, 400) });
    let parsed = null;
    try { parsed = JSON.parse(run.out.trim()); } catch { parsed = null; }
    return json(res, 200, { ok: true, detail: parsed });
  }

  if (req.method === "POST" && url.pathname === "/api/invite/edit") {
    const body = await readJsonBody(req);
    const alias = String(body?.alias ?? "").trim();
    if (!alias) return json(res, 400, { error: "alias is required" });
    const args = [OAUTH_SETUP, "--edit-invite", alias];
    if (body?.quota && Number.isInteger(Number(body.quota))) {
      args.push("--quota", String(body.quota));
    }
    if (body?.resetUsage) {
      args.push("--reset-usage");
    }
    const run = await runNode(args);
    if (run.code !== 0) return json(res, 500, { error: "failed to edit invite", detail: run.err.trim().slice(0, 400) });
    let parsed = null;
    try { parsed = JSON.parse(run.out.trim()); } catch { parsed = null; }
    return json(res, 200, { ok: true, detail: parsed });
  }

  if (req.method === "POST" && url.pathname === "/api/invite/delete") {
    const body = await readJsonBody(req);
    const alias = String(body?.alias ?? "").trim();
    if (!alias) return json(res, 400, { error: "alias is required" });
    const run = await runNode([OAUTH_SETUP, "--delete-invite", alias]);
    if (run.code !== 0) return json(res, 500, { error: "failed to delete invite", detail: run.err.trim().slice(0, 400) });
    let parsed = null;
    try { parsed = JSON.parse(run.out.trim()); } catch { parsed = null; }
    return json(res, 200, { ok: true, detail: parsed });
  }

  if (req.method === "POST" && url.pathname === "/api/release-stale") {
    const run = await runNode([OAUTH_SETUP, "--release-stale", "--force"]);
    if (run.code !== 0) return json(res, 500, { error: "release stale failed", detail: run.err.trim().slice(0, 400) });
    let parsed = null;
    try { parsed = JSON.parse(run.out.trim()); } catch { parsed = null; }
    return json(res, 200, { ok: true, detail: parsed });
  }

  if (req.method === "POST" && url.pathname === "/api/reset-tools") {
    if (!existsSync(DEFAULTS_PATH)) {
      return json(res, 409, { error: "defaults file missing", path: DEFAULTS_PATH });
    }
    const def = JSON.parse(await readFile(DEFAULTS_PATH, "utf8"));
    const allow = asStringArray(def.allowTools);
    const deny = asStringArray(def.denyTools);
    if (!allow.length) return json(res, 409, { error: "defaults file has no allowTools" });

    const overlap = allow.filter((n) => deny.includes(n));
    if (overlap.length) return json(res, 409, { error: "defaults file is inconsistent", overlap });

    const saved = await saveConfigAllowing(allow, deny);
    return json(res, 200, {
      ok: true,
      ...saved,
      counts: { allow: allow.length, deny: deny.length },
      restartRequired: saved.changed,
    });
  }

  if (req.method === "GET" && url.pathname === "/api/upstream/detect") {
    const detected = await detectWinHelmUpstream();
    return json(res, detected.ok ? 200 : 404, detected);
  }

  if (req.method === "POST" && url.pathname === "/api/upstream") {
    const body = await readJsonBody(req);
    const upstreamUrl = String(body?.upstreamUrl ?? "").trim();
    if (!/^https?:\/\/(127\.0\.0\.1|localhost):\d+(\/.*)?$/.test(upstreamUrl)) {
      return json(res, 400, { error: "URL ต้องเป็น http://127.0.0.1:<port>/... หรือ localhost" });
    }
    let tools;
    try {
      tools = await fetchInventory(upstreamUrl);
    } catch (err) {
      return json(res, 422, { error: `ไม่สามารถติดต่อ MCP ที่ URL นี้ได้: ${err?.message ?? err}` });
    }
    const saved = await saveConfigUpstream(upstreamUrl);
    let restartResult = null;
    if (body?.restart !== false) {
      restartResult = await restartGateway();
    }
    return json(res, 200, {
      ok: true,
      upstreamUrl,
      toolCount: tools.length,
      ...saved,
      restart: restartResult,
    });
  }

  if (req.method === "POST" && url.pathname === "/api/restart-gateway") {
    const result = await restartGateway();
    return json(res, 200, result);
  }

  if (req.method === "POST" && url.pathname === "/api/core/start") {
    const resCore = await startCoreProcess();
    return json(res, resCore.ok ? 200 : 500, resCore);
  }

  if (req.method === "POST" && url.pathname === "/api/core/stop") {
    const resCore = await stopCoreProcess();
    return json(res, 200, resCore);
  }

  if (req.method === "POST" && url.pathname === "/api/gateway/start") {
    const resGw = await restartGateway();
    return json(res, resGw.ok ? 200 : 500, resGw);
  }

  if (req.method === "POST" && url.pathname === "/api/all/start") {
    const resCore = await startCoreProcess();
    const resGw = await restartGateway();
    return json(res, 200, { core: resCore, gateway: resGw });
  }

  if (req.method === "GET" && url.pathname === "/api/services") {
    const cfg = await loadConfig();
    const corePort = (() => { try { return Number(new URL(cfg.upstreamUrl).port || 18790); } catch { return 18790; } })();
    const gwPort = Number(cfg.listenPort || 18788);
    const [coreUp, gwUp, funnelStatus] = await Promise.all([
      portListening(corePort),
      portListening(gwPort),
      getFunnelStatus(),
    ]);
    let gwHealth = null;
    if (gwUp) {
      gwHealth = await fetch(`http://127.0.0.1:${gwPort}/healthz`, { signal: AbortSignal.timeout(2000) })
        .then((r) => r.json()).catch(() => null);
    }
    const readPid = async (name) => {
      const p = path.join(ROOT, name);
      if (!existsSync(p)) return null;
      const raw = (await readFile(p, "utf8").catch(() => "")).trim();
      return /^\d+$/.test(raw) ? Number(raw) : null;
    };
    return json(res, 200, {
      core: { running: coreUp, pid: coreUp ? await readPid("core.pid") : null, port: corePort, url: cfg.upstreamUrl },
      gateway: { running: gwUp, pid: gwUp ? await readPid("gateway.pid") : null, port: gwPort, health: gwHealth },
      admin: { running: true, pid: process.pid, port: PORT },
      funnel: { configured: Boolean(cfg.oauth?.authority), active: funnelStatus.active, available: funnelStatus.available, authority: cfg.oauth?.authority ?? "", baseUrl: cfg.baseUrl ?? "" },
      startup: { enabled: existsSync(getStartupLinkPath()), path: getStartupLinkPath() },
    });
  }

  if (req.method === "POST" && url.pathname === "/api/funnel") {
    const body = await readJsonBody(req);
    const cfg = await loadConfig();
    const gwPort = Number(cfg.listenPort || 18788);
    const action = body?.action === "off" ? "off" : "on";
    const args = action === "off" ? ["funnel", "off"] : ["funnel", "--bg", String(gwPort)];
    const resCmd = await new Promise((resolve) => {
      const child = spawn("tailscale", args, { windowsHide: true });
      let out = "";
      let err = "";
      child.stdout.on("data", (d) => (out += d.toString("utf8")));
      child.stderr.on("data", (d) => (err += d.toString("utf8")));
      child.on("error", (e) => resolve({ code: 1, out: "", err: e.message }));
      child.on("exit", (code) => resolve({ code: code ?? 1, out: out.trim(), err: err.trim() }));
    });
    if (resCmd.code !== 0) return json(res, 500, { ok: false, error: resCmd.err || resCmd.out || "tailscale funnel failed" });
    return json(res, 200, { ok: true, action, out: resCmd.out });
  }

  if (req.method === "POST" && url.pathname === "/api/startup") {
    const body = await readJsonBody(req);
    const enabled = Boolean(body?.enabled);
    const lnkPath = getStartupLinkPath();
    if (!enabled) {
      if (existsSync(lnkPath)) {
        const { unlink } = await import("node:fs/promises");
        await unlink(lnkPath);
      }
      return json(res, 200, { ok: true, enabled: false });
    }
    const vbsPath = path.join(ROOT, "tray", "launch-tray.vbs");
    const icoPath = path.join(ROOT, "tray", "winhelm.ico");
    const ps = `$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('${lnkPath.replace(/'/g, "''")}'); $s.TargetPath = "$env:SystemRoot\\System32\\wscript.exe"; $s.Arguments = '"${vbsPath.replace(/'/g, "''")}"'; $s.WorkingDirectory = '${ROOT.replace(/'/g, "''")}'; $s.WindowStyle = 7; $s.IconLocation = '${icoPath.replace(/'/g, "''")},0'; $s.Description = 'WinHelm System Tray'; $s.Save()`;
    const run = await new Promise((resolve) => {
      const child = spawn("powershell.exe", ["-NoProfile", "-Command", ps], { windowsHide: true });
      let err = "";
      child.stderr.on("data", (d) => (err += d.toString("utf8")));
      child.on("exit", (code) => resolve({ code: code ?? 1, err: err.trim() }));
    });
    if (run.code !== 0) return json(res, 500, { ok: false, error: run.err || "failed to create startup shortcut" });
    return json(res, 200, { ok: true, enabled: true, path: lnkPath });
  }

  if (req.method === "POST" && url.pathname === "/api/gateway/stop") {
    const result = await stopGateway();
    return json(res, 200, result);
  }

  if (req.method === "GET" && url.pathname === "/api/logs") {
    const target = url.searchParams.get("target") === "gateway" ? "gateway" : "core";
    const files = target === "gateway"
      ? [path.join(ROOT, "gateway.stdout.log"), path.join(ROOT, "gateway.stdout.log.err")]
      : [path.join(ROOT, "core.stdout.log"), path.join(ROOT, "core.stderr.log")];
    const readTail = async (fp) => {
      if (!existsSync(fp)) return "";
      const txt = await readFile(fp, "utf8").catch(() => "");
      return txt
        .replace(/\x1b\[[0-9;]*m/g, "")
        .split(/\r?\n/)
        .slice(-120)
        .join("\n")
        .trim();
    };
    return json(res, 200, {
      target,
      stdout: await readTail(files[0]),
      stderr: await readTail(files[1]),
    });
  }

  if (req.method === "GET" && url.pathname === "/api/core/monitor") {
    const cfg = await loadConfig();
    const base = new URL(cfg.upstreamUrl);
    const origin = `${base.protocol}//${base.host}`;
    const token = getUpstreamAuthToken(cfg);
    const headers = token ? { authorization: `Bearer ${token}` } : {};
    const [statsRes, logsRes] = await Promise.allSettled([
      fetch(`${origin}/api/monitor/stats`, { headers, signal: AbortSignal.timeout(20000) }).then(async (r) => {
        if (!r.ok) throw new Error(`Core stats ${r.status}`);
        return r.json();
      }),
      fetch(`${origin}/api/monitor/logs`, { headers, signal: AbortSignal.timeout(8000) }).then(async (r) => {
        if (!r.ok) throw new Error(`Core logs ${r.status}`);
        return r.json();
      }),
    ]);

    if (statsRes.status === "fulfilled") globalThis.__lastCoreStats = statsRes.value;
    if (logsRes.status === "fulfilled") globalThis.__lastCoreLogs = logsRes.value?.logs ?? [];

    const stats = statsRes.status === "fulfilled" ? statsRes.value : (globalThis.__lastCoreStats ?? null);
    const logs = logsRes.status === "fulfilled" ? (logsRes.value?.logs ?? []) : (globalThis.__lastCoreLogs ?? []);

    if (!stats && statsRes.status === "rejected" && logsRes.status === "rejected") {
      return json(res, 502, { ok: false, error: String(statsRes.reason?.message ?? statsRes.reason) });
    }
    return json(res, 200, {
      ok: true,
      stale: statsRes.status === "rejected",
      stats,
      logs,
    });
  }

  if (req.method === "DELETE" && url.pathname === "/api/core/monitor/logs") {
    const cfg = await loadConfig();
    const base = new URL(cfg.upstreamUrl);
    const origin = `${base.protocol}//${base.host}`;
    const token = getUpstreamAuthToken(cfg);
    const headers = token ? { authorization: `Bearer ${token}` } : {};
    try {
      const r = await fetch(`${origin}/api/monitor/logs`, { method: "DELETE", headers, signal: AbortSignal.timeout(4000) });
      return json(res, r.ok ? 200 : 502, { ok: r.ok });
    } catch (err) {
      return json(res, 502, { ok: false, error: String(err?.message ?? err) });
    }
  }

  if (req.method === "GET" && url.pathname === "/api/core/jobs") {
    const run = await runWinHelmCli(["jobs"]);
    const out = run.out.trim();
    const normalizeJob = (job) => {
      const st = job.status ?? job.state ?? "";
      if (st !== "awaiting_approval" && st !== "pending") return job;
      let expMs = typeof job.expiresAt === "number" ? job.expiresAt : Number.NaN;
      if (!Number.isFinite(expMs) && typeof job.summary === "string") {
        const m = job.summary.match(/expires=([^\s·]+)/);
        if (m) expMs = Date.parse(m[1]);
      }
      return Number.isFinite(expMs) && expMs <= Date.now()
        ? { ...job, status: "expired", state: "expired" }
        : job;
    };
    try {
      const parsed = JSON.parse(out);
      const list = Array.isArray(parsed) ? parsed : (parsed.jobs ?? []);
      return json(res, 200, { ok: true, jobs: list.map(normalizeJob) });
    } catch {
      const jobs = out ? out.split(/\r?\n/).map((line) => {
        const parts = line.split("\t");
        if (parts.length < 3 || !parts[0].startsWith("job_")) return null;
        return normalizeJob({
          jobId: parts[0].trim(),
          status: parts[1].trim(),
          toolName: parts[2].trim(),
          summary: parts.slice(3).join(" · ").trim() || parts[0].trim(),
        });
      }).filter(Boolean) : [];
      return json(res, 200, { ok: run.code === 0, jobs });
    }
  }

  if (req.method === "POST" && url.pathname === "/api/core/jobs/decide") {
    const body = await readJsonBody(req);
    const jobId = String(body?.jobId ?? "").trim();
    const decision = body?.decision;
    const alwaysApprove = body?.alwaysApprove === true;
    const toolName = String(body?.toolName ?? "").trim();
    if (!jobId || !/^[A-Za-z0-9._:-]+$/.test(jobId)) {
      return json(res, 400, { error: "valid jobId is required" });
    }
    if (decision !== "approve" && decision !== "deny") {
      return json(res, 400, { error: "decision must be 'approve' or 'deny'" });
    }
    const decisionCliPath = resolveWinHelmCoreFile("dist", "cli", "decision-cli.js");
    if (decisionCliPath) {
      const { decideSharedApprovalJob } = await import(pathToFileURL(decisionCliPath).href);
      const outcome = await decideSharedApprovalJob(
        jobId,
        decision === "deny" ? "denied" : "approved",
        "console"
      );
      if (!outcome?.ok) {
        return json(res, 400, { ok: false, error: outcome?.message || "Approval decision failed" });
      }
      let policyUpdated = false;
      if (decision === "approve" && alwaysApprove && toolName) {
        policyUpdated = await alwaysAllowToolPolicy(toolName, jobId).catch(() => false);
      }
      return json(res, 200, { ok: true, jobId, decision, state: outcome.state, policyUpdated });
    }
    const run = await runWinHelmCli([decision, jobId]);
    if (run.code !== 0) return json(res, 500, { ok: false, error: run.err.trim() || run.out.trim() });
    let policyUpdated = false;
    if (decision === "approve" && alwaysApprove && toolName) {
      policyUpdated = await alwaysAllowToolPolicy(toolName).catch(() => false);
    }
    return json(res, 200, { ok: true, jobId, decision, out: run.out.trim(), policyUpdated });
  }

  if (req.method === "POST" && url.pathname === "/api/upstream-token") {
    const body = await readJsonBody(req);
    const action = String(body?.action ?? "set").trim();

    if (action === "sync") {
      const tokenFile = path.join(os.homedir(), ".winhelm", "auth-token");
      if (!existsSync(tokenFile)) {
        return json(res, 404, { error: "ไม่พบไฟล์ ~/.winhelm/auth-token" });
      }
      const diskToken = readFileSync(tokenFile, "utf8").trim();
      if (!diskToken) {
        return json(res, 400, { error: "ไฟล์ auth-token ว่างเปล่า" });
      }
      await saveConfigUpstreamToken(diskToken);
      if (body?.restart !== false) {
        await restartGateway();
      }
      return json(res, 200, { ok: true, source: "file", masked: `••••••••${diskToken.slice(-4)}` });
    } else if (action === "set") {
      const token = String(body?.token ?? "").trim();
      if (!token) return json(res, 400, { error: "Token ต้องไม่ว่างเปล่า" });
      await saveConfigUpstreamToken(token);
      if (body?.restart !== false) {
        await restartGateway();
      }
      return json(res, 200, { ok: true, source: "config", masked: `••••••••${token.slice(-4)}` });
    } else if (action === "clear") {
      await saveConfigUpstreamToken(null);
      if (body?.restart !== false) {
        await restartGateway();
      }
      const fallback = getUpstreamAuthInfo(await loadConfig());
      return json(res, 200, { ok: true, cleared: true, fallbackSource: fallback.source });
    }
    return json(res, 400, { error: "unknown action" });
  }

  if (req.method === "GET" && url.pathname === "/api/schema-v2") {
    const coreConfig = await loadWinHelmConfig();
    const isV2 = coreConfig?.schemaVersion === 2;
    const profilePreset = coreConfig?.profilePreset || coreConfig?.profile || "power";
    const terminalMode = coreConfig?.terminal?.mode || (coreConfig?.allowSystemExecution ? "full" : "safe");
    const toolPolicy = coreConfig?.toolPolicy || {};
    const folders = coreConfig?.folders || (coreConfig?.allowedDirectories ? coreConfig.allowedDirectories.map(p => ({ path: p, permission: "readwrite" })) : []);

    const toolsWithPolicy = CANONICAL_TOOLS.map((tool) => {
      let currentPolicy = "auto";
      if (isV2) {
        if (tool.name.startsWith("terminal_") || tool.name === "command_run") {
          currentPolicy = terminalMode === "full" ? "auto" : (terminalMode === "off" ? "off" : "ask");
        } else if (toolPolicy[tool.name]) {
          currentPolicy = toolPolicy[tool.name];
        } else {
          currentPolicy = tool.risk === "R0" || tool.risk === "R1" || tool.risk === "R2" || tool.risk === "R3" ? "auto" : (profilePreset === "power" ? "auto" : "ask");
        }
      } else {
        currentPolicy = "auto";
      }
      return {
        ...tool,
        policy: currentPolicy,
      };
    });

    const gwCfg = await loadConfig().catch(() => ({}));
    return json(res, 200, {
      schemaMode: isV2 ? "v2" : "legacy",
      profilePreset,
      terminalMode,
      folders,
      approvalMode: coreConfig?.approval?.mode || "smart",
      approvalUiMode: gwCfg?.approvalUiMode === "console_only" ? "console_only" : "tray_dialog",
      tools: toolsWithPolicy,
      totalTools: CANONICAL_TOOLS.length,
      configPath: resolveWinHelmConfigPath(),
    });
  }

  if (req.method === "POST" && url.pathname === "/api/schema-v2") {
    const body = await readJsonBody(req);
    const incomingPolicy = body?.toolPolicy || {};
    const terminalMode = body?.terminalMode || "full";
    const rawPreset = String(body?.profilePreset || "power").toLowerCase();
    const profilePreset = VALID_CORE_PRESETS.has(rawPreset)
      ? rawPreset
      : (terminalMode === "full" ? "power" : (terminalMode === "off" ? "safe" : "balanced"));
    const folders = Array.isArray(body?.folders) && body.folders.length > 0
      ? body.folders
      : [
          { path: "C:\\", permission: "readwrite" },
          { path: "D:\\", permission: "readwrite" }
        ];

    const existingCore = (await loadWinHelmConfig()) || {};

    const fullToolPolicy = {};
    for (const tool of CANONICAL_TOOLS) {
      if (["terminal_run", "terminal_task_start", "terminal_task_send", "terminal_task_kill", "command_run"].includes(tool.name)) {
        continue;
      }
      fullToolPolicy[tool.name] = incomingPolicy[tool.name] || (profilePreset === "safe" && tool.risk !== "R0" ? "off" : "auto");
    }
    fullToolPolicy.winhelm_status = "auto";
    fullToolPolicy.winhelm_job_status = "auto";

    const v2Config = {
      schemaVersion: 2,
      profilePreset,
      folders,
      terminal: {
        mode: terminalMode,
        approvalTtlSeconds: 300
      },
      toolPolicy: fullToolPolicy,
      approval: {
        mode: body?.approvalMode || "smart",
        channels: ["cli", "toast"],
        blockHoldMs: 60000,
        jobTtlMs: 300000,
        maxPending: 20
      },
      network: {
        allowLoopback: true
      },
      blockedCommands: existingCore.blockedCommands || [
        "format-volume", "format-disk", "clear-disk", "stop-computer", "restart-computer",
        "rmdir /s /q c:\\", "del /f /s /q c:\\", "remove-item -recurse -force c:\\"
      ],
      allowSystemExecution: terminalMode !== "off",
      fileReadLineLimit: existingCore.fileReadLineLimit || 2000,
      defaultTimeoutMs: existingCore.defaultTimeoutMs || 60000,
      telemetryEnabled: existingCore.telemetryEnabled || false,
      rateLimitPerMinute: existingCore.rateLimitPerMinute || 120,
      preferPwsh: existingCore.preferPwsh !== false
    };

    const savedCore = await saveWinHelmConfig(v2Config);

    const allowTools = [];
    const denyTools = [];
    for (const tool of CANONICAL_TOOLS) {
      const pol = incomingPolicy[tool.name] || fullToolPolicy[tool.name] || (terminalMode === "off" ? "off" : "auto");
      if (pol === "off") {
        denyTools.push(tool.name);
      } else {
        allowTools.push(tool.name);
      }
    }
    const approvalUiMode = body?.approvalUiMode === "console_only" ? "console_only" : "tray_dialog";
    const savedGw = await saveConfigAllowing(allowTools, denyTools, { approvalUiMode });

    let coreRestartResult = null;
    let gwRestartResult = null;
    if (body?.restart !== false) {
      await stopCoreProcess();
      coreRestartResult = await startCoreProcess();
      gwRestartResult = await restartGateway();
    }

    return json(res, 200, {
      ok: true,
      backup: savedCore.backup,
      gwBackup: savedGw.backup,
      schemaMode: "v2",
      toolCounts: {
        auto: Object.values(fullToolPolicy).filter(v => v === "auto").length + (terminalMode === "full" ? 5 : 0),
        ask: Object.values(fullToolPolicy).filter(v => v === "ask").length + (terminalMode === "ask" ? 5 : 0),
        off: Object.values(fullToolPolicy).filter(v => v === "off").length + (terminalMode === "off" ? 5 : 0),
      },
      coreRestart: coreRestartResult,
      gwRestart: gwRestartResult,
    });
  }

  return json(res, 404, { error: "not found" });
}

// ------------------------------------------------------------- winhelm core control

async function startCoreProcess() {
  const script = path.join(ROOT, "start-core.ps1");
  return new Promise((resolve) => {
    const child = spawn("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script], {
      cwd: ROOT,
      windowsHide: true,
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d.toString("utf8")));
    child.stderr.on("data", (d) => (err += d.toString("utf8")));
    child.on("exit", (code) => {
      resolve({ ok: code === 0, out: out.trim(), err: err.trim() });
    });
  });
}

async function stopCoreProcess() {
  const script = path.join(ROOT, "stop-core.ps1");
  return new Promise((resolve) => {
    const child = spawn("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script], {
      cwd: ROOT,
      windowsHide: true,
    });
    let out = "";
    child.stdout.on("data", (d) => (out += d.toString("utf8")));
    child.on("exit", (code) => {
      resolve({ ok: true, out: out.trim() });
    });
  });
}

// ------------------------------------------------------------- gateway restart

async function restartGateway() {
  const cfg = await loadConfig();
  const pidPath = path.join(ROOT, "gateway.pid");

  let stoppedPid = null;
  if (existsSync(pidPath)) {
    const raw = (await readFile(pidPath, "utf8")).trim();
    if (/^\d+$/.test(raw)) {
      const pid = Number(raw);
      const cim = await new Promise((resolve) => {
        const p = spawn("powershell.exe", ["-NoProfile", "-Command",
          `Get-CimInstance Win32_Process -Filter "ProcessId=${pid}" | Select-Object -ExpandProperty CommandLine`],
          { windowsHide: true });
        let out = "";
        p.stdout.on("data", (d) => (out += d.toString("utf8")));
        p.on("exit", () => resolve(out.trim()));
      });
      // guard: only stop it when it is really our gateway
      if (/winhelm-console-gateway[\\/]server\.js/.test(cim)) {
        try {
          process.kill(pid, "SIGTERM");
          stoppedPid = pid;
        } catch {
          /* already gone */
        }
        await new Promise((r) => setTimeout(r, 900));
      }
    }
  }

  const child = spawn("node", [path.join(ROOT, "server.js")], {
    cwd: ROOT, detached: true, stdio: "ignore", windowsHide: true,
  });
  child.unref();
  await writeFile(pidPath, String(child.pid), "ascii");
  await new Promise((r) => setTimeout(r, 700));

  const health = await fetch(`http://127.0.0.1:${cfg.listenPort}/healthz`, { signal: AbortSignal.timeout(3000) })
    .then((r) => r.json()).catch((e) => ({ ok: false, error: String(e?.message ?? e) }));

  return { ok: Boolean(health?.ok), stoppedPid, startedPid: child.pid, health };
}

async function stopGateway() {
  const cfg = await loadConfig();
  const pidPath = path.join(ROOT, "gateway.pid");
  const port = Number(cfg.listenPort || 18788);
  let stoppedPid = null;

  if (existsSync(pidPath)) {
    const raw = (await readFile(pidPath, "utf8").catch(() => "")).trim();
    if (/^\d+$/.test(raw)) {
      const pid = Number(raw);
      try {
        process.kill(pid, "SIGTERM");
        stoppedPid = pid;
      } catch {}
    }
  }
  if (!stoppedPid) {
    await new Promise((resolve) => {
      const p = spawn("powershell.exe", ["-NoProfile", "-Command",
        `$c = Get-NetTCPConnection -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; if ($c) { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue; Write-Output $c.OwningProcess }`],
        { windowsHide: true });
      let out = "";
      p.stdout.on("data", (d) => (out += d.toString("utf8")));
      p.on("exit", () => { if (/^\d+$/.test(out.trim())) stoppedPid = Number(out.trim()); resolve(); });
    });
  }
  await new Promise((r) => setTimeout(r, 400));
  return { ok: !(await portListening(port)), stoppedPid };
}

// ---------------------------------------------------------------------- server

const indexPath = path.join(HERE, "index.html");

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", `http://${HOST}:${PORT}`);

    if (!hostOk(req)) return json(res, 421, { error: "bad host" });
    if (!originOk(req)) return json(res, 403, { error: "cross-origin request rejected" });

    if (req.method === "GET" && url.pathname === "/__launch") {
      const ticket = url.searchParams.get("t") ?? "";
      const fresh = Date.now() - launchTicketIssuedAt < LAUNCH_TICKET_TTL_MS;
      if (launchTicketUsed || !fresh || !safeEqual(ticket, LAUNCH_TICKET)) {
        return send(res, 403, "launch ticket is invalid, used, or expired", "text/plain; charset=utf-8");
      }
      launchTicketUsed = true;
      res.writeHead(302, {
        location: "/",
        "set-cookie": `${COOKIE_NAME}=${TOKEN}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`,
        "cache-control": "no-store",
      });
      return res.end();
    }

    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/invites" || url.pathname === "/tools" || url.pathname === "/services" || url.pathname === "/logs" || url.pathname === "/monitor")) {
      const html = await readFile(indexPath);
      return send(res, 200, html, "text/html; charset=utf-8");
    }

    if (req.method === "GET" && (url.pathname === "/logo.png" || url.pathname === "/favicon.ico")) {
      const logoFile = path.join(HERE, url.pathname === "/favicon.ico" && existsSync(path.join(HERE, "favicon.ico")) ? "favicon.ico" : "logo.png");
      if (existsSync(logoFile)) {
        const data = await readFile(logoFile);
        return send(res, 200, data, logoFile.endsWith(".ico") ? "image/x-icon" : "image/png");
      }
      return send(res, 404, "", "text/plain");
    }

    if (url.pathname.startsWith("/api/")) return handleApi(req, res, url);

    return json(res, 404, { error: "not found" });
  } catch (err) {
    return json(res, err?.status ?? 500, { error: String(err?.message ?? err) });
  }
});

server.listen(PORT, HOST, () => {
  const fromEnv = typeof ENV_TOKEN === "string" && ENV_TOKEN.length >= 32;
  if (fromEnv) {
    // The launcher already holds both the token and the ticket, so nothing secret is printed.
    // Only a fingerprint is logged, enough to correlate the launcher with this process.
    const fingerprint = createHash("sha256").update(LAUNCH_TICKET).digest("hex").slice(0, 12).toUpperCase();
    console.log(JSON.stringify({ event: "ADMIN_READY", port: PORT, token_source: "launcher", ticket_fingerprint: fingerprint }));
  } else {
    const url = `http://${HOST}:${PORT}/#${TOKEN}`;
    console.log(JSON.stringify({ event: "ADMIN_READY", port: PORT, url }));
    // Only an internally generated token is printed, for a human to open the page once.
    console.log(`open: ${url}`);
  }
});

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    server.close(() => process.exit(0));
  });
}
