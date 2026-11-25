// Operator CLI for the lnwjud OAuth layer.
//
//   node oauth-setup.mjs --status
//   node oauth-setup.mjs --init-client --redirect-uri <exact URI from Gemini>
//   node oauth-setup.mjs --reset-client --redirect-uri <same URI>
//   node oauth-setup.mjs --copy-secret
//   node oauth-setup.mjs --invite <alias>
//   node oauth-setup.mjs --copy-invite <alias>
//
// Secrets exist in three places only: the store's hash, a Windows-user DPAPI file,
// and the clipboard. They are never printed to stdout. Every clipboard handoff is
// read back and compared before the command reports success, because a silent
// clipboard loss already cost two setup rounds on this project.

import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync, existsSync, unlinkSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { RegistrationStore, defaultR7StorePath } from "./oauth/r7_store.mjs";
import { sha256Hex } from "./oauth/r7_oauth.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// One secret file per client so several MCP clients can coexist. The old single-client
// filename is still read for the install that predates this.
const LEGACY_SECRET_FILE = "gemini-client-secret.dpapi";
const safeId = (id) => String(id).replace(/[^A-Za-z0-9._-]/g, "_");
const secretFileFor = (clientId) => `client-secret-${safeId(clientId)}.dpapi`;
const legacySecretPath = () => path.join(HERE, LEGACY_SECRET_FILE);

function loadConfig() {
  const idx = process.argv.indexOf("--config");
  const file = idx > -1 ? process.argv[idx + 1] : path.join(HERE, "config.json");
  if (!existsSync(file)) throw new Error(`config not found: ${file}`);
  return JSON.parse(readFileSync(file, "utf8"));
}

function arg(name, fallback = null) {
  const i = process.argv.indexOf(name);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

function pwsh(script, stdinText) {
  return new Promise((resolve) => {
    const child = execFile(
      "pwsh.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { timeout: 30000 },
      (err, stdout, stderr) => {
        if (err) return resolve({ ok: false, detail: (stderr || err.message).trim() });
        resolve({ ok: true, out: String(stdout).trim() });
      },
    );
    if (stdinText !== undefined) child.stdin.end(stdinText, "utf8");
  });
}

async function setClipboardVerified(value) {
  const script = `$ErrorActionPreference='Stop'
$v = [Console]::In.ReadToEnd()
Set-Clipboard -Value $v
$back = Get-Clipboard -Raw
if ($null -ne $back -and $back.TrimEnd("\`r","\`n") -ceq $v) { 'MATCH' } else { 'MISMATCH' }`;
  const r = await pwsh(script, value);
  if (!r.ok) return { ok: false, detail: r.detail };
  const ok = r.out.includes("MATCH");
  return { ok, detail: ok ? "verified" : "clipboard did not keep the value" };
}

async function saveDpapi(value, file) {
  // DPAPI CurrentUser scope, written as the standard SecureString blob form.
  const script = `$ErrorActionPreference='Stop'
$v = [Console]::In.ReadToEnd()
$sec = ConvertTo-SecureString -String $v -AsPlainText -Force
$enc = ConvertFrom-SecureString -SecureString $sec
[IO.File]::WriteAllText('${file.replace(/'/g, "''")}', $enc, [Text.Encoding]::UTF8)
'WRITTEN'`;
  const r = await pwsh(script, value);
  if (!r.ok || !r.out.includes("WRITTEN")) throw new Error(`DPAPI write failed: ${r.detail ?? "unknown"}`);
}

async function readDpapi(file) {
  if (!existsSync(file)) throw new Error(`DPAPI file missing: ${file}`);
  const script = `$ErrorActionPreference='Stop'
$enc = Get-Content -LiteralPath '${file.replace(/'/g, "''")}' -Raw
$sec = ConvertTo-SecureString -String $enc
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
try { [Console]::Out.Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }`;
  const r = await pwsh(script);
  if (!r.ok) throw new Error(`DPAPI read failed: ${r.detail}`);
  return r.out.trim();
}

function inviteFile(alias) {
  return path.join(HERE, `invite-${alias.replace(/[^A-Za-z0-9._-]/g, "_")}.dpapi`);
}

async function openStore(cfg) {
  const storePath = cfg.oauth?.storePath
    ? path.resolve(HERE, cfg.oauth.storePath)
    : defaultR7StorePath();
  return { store: new RegistrationStore({ storePath }), storePath };
}

async function createClient({ store, storePath, clientId, redirectUri }) {
  let parsed;
  try {
    parsed = new URL(redirectUri);
  } catch {
    throw new Error("--redirect-uri is not a valid URL");
  }
  if (parsed.protocol !== "https:" || parsed.hostname !== "oauth-redirect.googleusercontent.com") {
    throw new Error("--redirect-uri must be https on oauth-redirect.googleusercontent.com");
  }

  const clientSecret = randomBytes(36).toString("base64url");
  const client = await store.ensureStaticOAuthClient({
    clientId,
    clientName: "lnwjud gemini web",
    clientSecret,
    redirectUris: [redirectUri],
    omitIss: true,
    htmlHandoff: true,
  });

  const fileName = secretFileFor(clientId);
  await saveDpapi(clientSecret, path.join(HERE, fileName));
  const clip = await setClipboardVerified(clientSecret);

  return {
    event: "STATIC_CLIENT_READY",
    storePath,
    client_id: client.client_id,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    redirect_uris: client.redirect_uris,
    omit_iss: client.omit_iss,
    secret_sha256_fingerprint: sha256Hex(clientSecret).slice(0, 12),
    secret_storage: `DPAPI (${fileName}) + clipboard`,
    clipboard: clip.detail,
    recover_with: `node oauth-setup.mjs --copy-secret --client-id ${clientId}`,
  };
}

async function main() {
  const cfg = loadConfig();
  const { store, storePath } = await openStore(cfg);
  const configuredClientId = cfg.oauth?.clientId ?? arg("--client-id");

  if (process.argv.includes("--status")) {
    const snap = await store.snapshot();
    console.log(JSON.stringify({
      storePath,
      clients: snap.staticOAuthClients.map((c) => ({
        client_id: c.client_id,
        status: c.status,
        auth: c.token_endpoint_auth_method,
        redirect_uris: c.redirect_uris,
        omit_iss: c.omit_iss,
      })),
      invites: snap.registrationInvites.map((i) => ({
        alias: i.alias_name,
        status: i.status,
        used: `${i.quota_epoch_used}/${i.quota_epoch_max}`,
      })),
      grants: snap.oauthGrants.map((g) => ({ status: g.status, expires: g.access_token_expires_at })),
      bindings: snap.installationBindings.length,
      registrations: snap.registeredInstallations.length,
      clients_secret: snap.staticOAuthClients.map((c) => ({
        client_id: c.client_id,
        secret_file: secretFileFor(c.client_id),
        available: existsSync(path.join(HERE, secretFileFor(c.client_id)))
          || (snap.staticOAuthClients.length === 1 && existsSync(legacySecretPath())),
      })),
    }, null, 2));
    return;
  }

  if (process.argv.includes("--init-client") || process.argv.includes("--reset-client")) {
    const reset = process.argv.includes("--reset-client");
    const redirectUri = arg("--redirect-uri");
    const clientId = arg("--client-id") ?? configuredClientId;
    if (!clientId) throw new Error("client id unknown: pass --client-id or set oauth.clientId in config.json");
    if (!redirectUri) throw new Error("--redirect-uri is required");

    if (reset) {
      const snap = await store.snapshot();
      const existing = snap.staticOAuthClients.find((c) => c.client_id === clientId);
      if (!existing) throw new Error(`nothing to reset: client ${clientId} not found`);
      await store._mutate((state) => {
        const at = new Date(store.now()).toISOString();
        for (const g of state.oauthGrants) {
          if (g.client_id === clientId && g.status === "active") {
            g.status = "revoked";
            g.revocation_reason = "CLIENT_RESET";
            g.revoked_at = at;
            g.record_revision += 1;
          }
        }
        state.staticOAuthClients = state.staticOAuthClients.filter((c) => c.client_id !== clientId);
      });
    }

    console.log(JSON.stringify(await createClient({ store, storePath, clientId, redirectUri }), null, 2));
    return;
  }

  if (process.argv.includes("--copy-secret")) {
    const wantedId = arg("--client-id") ?? configuredClientId ?? arg("--client-id");
    if (!wantedId) throw new Error("--client-id is required (or set oauth.clientId in config.json)");
    let file = path.join(HERE, secretFileFor(wantedId));
    let source = secretFileFor(wantedId);

    if (!existsSync(file)) {
      // Backward compatibility: a single-client install keeps its secret in the legacy file.
      const snap = await store.snapshot();
      if (snap.staticOAuthClients.length === 1 && existsSync(legacySecretPath())) {
        file = legacySecretPath();
        source = LEGACY_SECRET_FILE;
      } else {
        throw new Error(`no stored secret for ${wantedId}. Migrate it: node oauth-setup.mjs --import-legacy-secret ${wantedId}`);
      }
    }

    const value = await readDpapi(file);
    const clip = await setClipboardVerified(value);
    console.log(JSON.stringify({
      event: "CLIENT_SECRET_COPIED",
      client_id: wantedId,
      source,
      fingerprint: sha256Hex(value).slice(0, 12),
      clipboard: clip.detail,
    }, null, 2));
    return;
  }

  if (process.argv.includes("--remove-client")) {
    const targetId = arg("--remove-client");
    if (!targetId) throw new Error("usage: --remove-client <client-id>");
    const result = await store._mutate((state) => {
      const at = new Date(store.now()).toISOString();
      let revoked = 0;
      for (const g of state.oauthGrants) {
        if (g.client_id === targetId && g.status === "active") {
          g.status = "revoked";
          g.revocation_reason = "CLIENT_REMOVED";
          g.revoked_at = at;
          g.record_revision += 1;
          revoked += 1;
        }
      }
      const before = state.staticOAuthClients.length;
      state.staticOAuthClients = state.staticOAuthClients.filter((c) => c.client_id !== targetId);
      return { removed: before - state.staticOAuthClients.length, revoked };
    });
    console.log(JSON.stringify({ event: "CLIENT_REMOVED", client_id: targetId, ...result,
      note: "also delete its client-secret-*.dpapi file if you created one" }, null, 2));
    return;
  }

  if (process.argv.includes("--list-clients")) {
    const snap = await store.snapshot();
    console.log(JSON.stringify({
      storePath,
      primaryClientId: configuredClientId ?? null,
      clients: snap.staticOAuthClients.map((c) => ({
        client_id: c.client_id,
        status: c.status,
        redirect_uris: c.redirect_uris,
        secret_file: secretFileFor(c.client_id),
        secret_available: existsSync(path.join(HERE, secretFileFor(c.client_id)))
          || (snap.staticOAuthClients.length === 1 && existsSync(legacySecretPath())),
        access_tokens_active: snap.oauthGrants.filter((g) => g.client_id === c.client_id && g.status === "active").length,
      })),
    }, null, 2));
    return;
  }

  if (process.argv.includes("--import-legacy-secret")) {
    const targetId = arg("--import-legacy-secret");
    if (!targetId) throw new Error("usage: --import-legacy-secret <client-id>");
    if (!existsSync(legacySecretPath())) throw new Error(`legacy secret not found: ${LEGACY_SECRET_FILE}`);
    const snap = await store.snapshot();
    const client = snap.staticOAuthClients.find((c) => c.client_id === targetId);
    if (!client) throw new Error(`client ${targetId} not found in the store`);

    // Verify the legacy secret actually belongs to this client before adopting it.
    const value = await readDpapi(legacySecretPath());
    try {
      await store.authenticateTokenClient({ clientId: targetId, clientSecret: value });
    } catch {
      throw new Error(`legacy secret does not match client ${targetId} — refusing to import`);
    }

    const fileName = secretFileFor(targetId);
    await saveDpapi(value, path.join(HERE, fileName));
    console.log(JSON.stringify({
      event: "LEGACY_SECRET_IMPORTED",
      client_id: targetId,
      to: fileName,
      legacy_left_untouched: true,
      fingerprint: sha256Hex(value).slice(0, 12),
    }, null, 2));
    return;
  }

  if (process.argv.includes("--invite")) {
    const alias = arg("--invite");
    if (!alias) throw new Error("--invite needs an alias name");
    const quotaParam = arg("--quota");
    const quotaMax = quotaParam && Number.isInteger(Number(quotaParam)) && Number(quotaParam) > 0 ? Number(quotaParam) : 1;
    const created = await store.createInvite({ aliasName: alias, quotaMax });
    const credential = created.registration_invite_credential ?? created.credential;
    if (!credential) throw new Error("store did not return a plaintext invite credential");
    const file = inviteFile(alias);
    await saveDpapi(credential, file);
    const clip = await setClipboardVerified(credential);
    console.log(JSON.stringify({
      event: "INVITE_READY",
      alias,
      invite_id: created.invite?.registration_invite_id ?? created.registration_invite_id ?? null,
      quota: `0/${quotaMax}`,
      storage: `DPAPI (${path.basename(file)}) + clipboard`,
      fingerprint: sha256Hex(credential).slice(0, 12),
      clipboard: clip.detail,
      recover_with: `node oauth-setup.mjs --copy-invite ${alias}`,
    }, null, 2));
    return;
  }

  if (process.argv.includes("--list-invites")) {
    const snap = await store.snapshot();
    const activeGrantBindings = new Set(
      (snap.oauthGrants ?? []).filter((g) => g.status === "active").map((g) => g.binding_id),
    );
    const list = (snap.registrationInvites ?? []).map((i) => {
      const dpapi = existsSync(inviteFile(i.alias_name));
      const myBindings = (snap.installationBindings ?? []).filter((b) => b.registration_invite_id === i.registration_invite_id);
      const activeGrants = myBindings.filter((b) => activeGrantBindings.has(b.binding_id)).length;
      const reserved = i.registrations_reserved ?? 0;
      const consumed = Math.max(i.quota_epoch_used, activeGrants);
      const pendingReserved = Math.max(0, reserved - activeGrants);
      const totalClaimed = consumed + pendingReserved;
      const exhausted = i.quota_epoch_max !== null && totalClaimed >= i.quota_epoch_max;
      return {
        id: i.registration_invite_id,
        alias: i.alias_name,
        status: i.status,
        used: consumed,
        max: i.quota_epoch_max,
        reserved: pendingReserved,
        active_grants: activeGrants,
        has_dpapi: dpapi,
        exhausted,
        usable: !exhausted && dpapi && i.status === "active",
        created_at: i.created_at,
        expires_at: i.expires_at,
      };
    });
    console.log(JSON.stringify(list, null, 2));
    return;
  }

  if (process.argv.includes("--revoke-invite")) {
    const alias = arg("--revoke-invite");
    if (!alias) throw new Error("--revoke-invite needs an alias name");
    const snap = await store.snapshot();
    const invite = snap.registrationInvites.find((i) => i.alias_name === alias);
    if (!invite) throw new Error(`invite "${alias}" not found`);
    const actionId = `operator_revoke_${Date.now()}`;
    await store.revokeInvite(invite.registration_invite_id, actionId, "operator_revoked");
    const file = inviteFile(alias);
    if (existsSync(file)) {
      try { unlinkSync(file); } catch {}
    }
    console.log(JSON.stringify({ event: "INVITE_REVOKED", alias, invite_id: invite.registration_invite_id }, null, 2));
    return;
  }

  if (process.argv.includes("--edit-invite")) {
    const alias = arg("--edit-invite");
    if (!alias) throw new Error("--edit-invite needs an alias name");
    const quotaParam = arg("--quota");
    const quota = quotaParam && Number.isInteger(Number(quotaParam)) && Number(quotaParam) > 0 ? Number(quotaParam) : null;
    const reset = process.argv.includes("--reset-usage");
    const updated = await store._mutate((state) => {
      const invite = state.registrationInvites.find((i) => i.alias_name === alias);
      if (!invite) throw new Error(`invite "${alias}" not found`);
      if (quota !== null) invite.quota_epoch_max = quota;
      if (reset) {
        invite.quota_epoch_used = 0;
        invite.registrations_reserved = 0;
        invite.status = "active";
      }
      if (invite.status === "exhausted" && (invite.quota_epoch_max === null || invite.quota_epoch_used < invite.quota_epoch_max)) {
        invite.status = "active";
      }
      invite.record_revision = (invite.record_revision ?? 1) + 1;
      return { alias: invite.alias_name, used: invite.quota_epoch_used, max: invite.quota_epoch_max, status: invite.status };
    });
    console.log(JSON.stringify({ event: "INVITE_UPDATED", ...updated }, null, 2));
    return;
  }

  if (process.argv.includes("--delete-invite")) {
    const alias = arg("--delete-invite");
    if (!alias) throw new Error("--delete-invite needs an alias name");
    const updated = await store._mutate((state) => {
      const idx = state.registrationInvites.findIndex((i) => i.alias_name === alias);
      if (idx === -1) throw new Error(`invite "${alias}" not found`);
      const inv = state.registrationInvites[idx];
      state.registrationReservations = state.registrationReservations.filter((r) => r.registration_invite_id !== inv.registration_invite_id);
      state.registrationInvites.splice(idx, 1);
      return { alias, id: inv.registration_invite_id };
    });
    const file = inviteFile(alias);
    if (existsSync(file)) {
      try { unlinkSync(file); } catch {}
    }
    console.log(JSON.stringify({ event: "INVITE_DELETED", ...updated }, null, 2));
    return;
  }

  if (process.argv.includes("--copy-invite")) {
    const alias = arg("--copy-invite");
    if (!alias) throw new Error("--copy-invite needs the alias name");
    const value = await readDpapi(inviteFile(alias));
    const clip = await setClipboardVerified(value);
    console.log(JSON.stringify({
      event: "INVITE_COPIED",
      alias,
      source: path.basename(inviteFile(alias)),
      fingerprint: sha256Hex(value).slice(0, 12),
      clipboard: clip.detail,
    }, null, 2));
    return;
  }

  if (process.argv.includes("--set-redirect")) {
    const redirectUri = arg("--redirect-uri");
    const clientId = arg("--client-id") ?? configuredClientId;
    if (!redirectUri) throw new Error("--redirect-uri is required");
    let parsed;
    try {
      parsed = new URL(redirectUri);
    } catch {
      throw new Error("--redirect-uri is not a valid URL");
    }
    if (parsed.protocol !== "https:" || parsed.hostname !== "oauth-redirect.googleusercontent.com") {
      throw new Error("--redirect-uri must be https on oauth-redirect.googleusercontent.com");
    }
    const updated = await store._mutate((state) => {
      const client = state.staticOAuthClients.find((c) => c.client_id === clientId);
      if (!client) throw new Error(`client ${clientId} not found`);
      const before = [...client.redirect_uris];
      client.redirect_uris = [redirectUri];
      client.record_revision = (client.record_revision ?? 1) + 1;
      client.last_used_at = client.last_used_at ?? null;
      return { client_id: client.client_id, before, after: client.redirect_uris };
    });
    console.log(JSON.stringify({ event: "REDIRECT_URI_UPDATED", ...updated, secret_unchanged: true }, null, 2));
    return;
  }

  if (process.argv.includes("--release-stale")) {
    const force = process.argv.includes("--force");
    const snap = await store.snapshot();
    const liveBindingIds = new Set(
      snap.oauthGrants.filter((g) => g.status === "active").map((g) => g.binding_id),
    );
    const stale = snap.installationBindings.filter(
      (b) =>
        b.binding_state === "provisional" &&
        !b.registration_id &&
        !liveBindingIds.has(b.binding_id) &&
        (force || (Date.now() - new Date(b.created_at).getTime() > 5 * 60 * 1000)),
    );
    const released = [];
    for (const b of stale) {
      try {
        const r = await store.releaseEnrollmentReservation(b.binding_id, null, "operator_release_stale");
        released.push({ binding: b.binding_id, released: r?.released ?? false, reason: r?.reason ?? "released" });
      } catch (err) {
        released.push({ binding: b.binding_id, released: false, reason: err?.message ?? "error" });
      }
    }
    const after = await store.snapshot();
    console.log(JSON.stringify({
      event: "STALE_RESERVATIONS_RELEASED",
      candidates: stale.length,
      detail: released,
      invites: after.registrationInvites.map((i) => ({
        alias: i.alias_name,
        used: `${i.quota_epoch_used}/${i.quota_epoch_max}`,
        reserved: i.registrations_reserved,
      })),
    }, null, 2));
    return;
  }

  if (process.argv.includes("--revoke-grants")) {
    const revoked = await store._mutate((state) => {
      const at = new Date(store.now()).toISOString();
      let n = 0;
      for (const g of state.oauthGrants) {
        if (g.status === "active") {
          g.status = "revoked";
          g.revocation_reason = "OPERATOR_REVOCATION";
          g.revoked_at = at;
          g.record_revision += 1;
          n += 1;
        }
      }
      return n;
    });
    console.log(JSON.stringify({ event: "GRANTS_REVOKED", count: revoked }, null, 2));
    return;
  }

  console.log([
    "usage:",
    "  node oauth-setup.mjs --status",
    "  node oauth-setup.mjs --list-clients",
    "  node oauth-setup.mjs --init-client --redirect-uri <uri> [--client-id <id>]",
    "  node oauth-setup.mjs --reset-client --redirect-uri <uri> [--client-id <id>]   (rotates a lost secret)",
    "  node oauth-setup.mjs --set-redirect --redirect-uri <uri> [--client-id <id>]   (Gemini rotates its redirect id)",
    "  node oauth-setup.mjs --copy-secret [--client-id <id>]",
    "  node oauth-setup.mjs --invite <alias>",
    "  node oauth-setup.mjs --copy-invite <alias>",
    "  node oauth-setup.mjs --revoke-grants",
    "  node oauth-setup.mjs --release-stale",
    "  node oauth-setup.mjs --remove-client <client-id>",
    "  node oauth-setup.mjs --import-legacy-secret <client-id>",
    "",
    "  --config <file>   operate on a different config (default: config.json next to this script)",
  ].join("\n"));
}

main().catch((err) => {
  const msg = String(err?.message ?? err);
  if (msg.includes("configuration mismatch")) {
    console.error("error: client already exists with a different secret.");
    console.error("       if the secret is lost, rotate it:  node oauth-setup.mjs --reset-client --redirect-uri <same URI>");
  } else {
    console.error(`error: ${msg}`);
  }
  process.exitCode = 1;
});
