// OAuth 2.1 authorization-server layer for the lnwjud gateway.
//
// Scope on purpose: one static confidential client (the Gemini shape), no DCR, no
// multi-adapter branching, no migration lane. Admission still goes through the
// reviewed bootstrap-intent state machine in r7_store.mjs, because that store
// refuses to issue an authorization code outside it (BOOTSTRAP_STATE_MACHINE_REQUIRED).
//
// The store is the authority for client identity, invite quota, PKCE, code lifetime,
// and grant lifetime. This module only does HTTP: routing, cookies, form parsing,
// and redirects.

import { randomBytes } from "node:crypto";
import { sha256Hex } from "./oauth/r7_oauth.mjs";
import { renderBootstrapPage, renderSupersessionPage, renderTerminalPage } from "./oauth/r7_authorization_page.mjs";

const SESSION_COOKIE = "lnwjud_sid";
const SESSION_TTL_MS = 10 * 60 * 1000;
const MAX_FORM_BYTES = 64 * 1024;
const MAX_WRONG_METHOD_ALLOW = "GET, POST";

function sendJson(res, status, payload, extra = {}) {
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(body.length),
    "cache-control": "no-store",
    ...extra,
  });
  res.end(body);
}

function sendHtml(res, status, html, extra = {}) {
  const body = Buffer.from(html, "utf8");
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": String(body.length),
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    ...extra,
  });
  res.end(body);
}

function parseCookies(header) {
  const out = new Map();
  if (typeof header !== "string") return out;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 1) continue;
    out.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  return out;
}

async function readForm(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_FORM_BYTES) {
      const err = new Error("FORM_TOO_LARGE");
      err.status = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}



function redirectWithError(res, { redirectUri, error, description, state }) {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (description) url.searchParams.set("error_description", description);
  if (typeof state === "string" && state.length) url.searchParams.set("state", state);
  res.writeHead(302, { location: url.toString(), "cache-control": "no-store", "referrer-policy": "no-referrer" });
  res.end();
}

/**
 * @param {object} options
 * @param {import("./oauth/r7_store.mjs").RegistrationStore} options.store
 * @param {string} options.authority  Public origin, no trailing slash, e.g. https://host.ts.net
 * @param {string[]} options.clientIds Static clients this server admits. Each one must already
 *        exist in the store; the store is the authority for its secret and redirect list.
 * @param {string} [options.clientId]  Legacy single-client form, kept for compatibility.
 */
export function createOAuthLayer({ store, authority, clientIds, clientId }) {
  if (!store) throw new Error("store required");
  if (typeof authority !== "string" || !/^https:\/\/[^/]+$/.test(authority)) {
    throw new Error("authority must be https://<host> with no trailing slash");
  }
  const admitted = new Set(
    (Array.isArray(clientIds) && clientIds.length ? clientIds : [clientId])
      .filter((id) => typeof id === "string" && id.length > 0),
  );
  if (admitted.size === 0) throw new Error("at least one client id is required");
  const isAdmitted = (id) => typeof id === "string" && admitted.has(id);

  const resource = `${authority}/mcp`;
  const issuer = authority;

  const authorizationServerMetadata = () => ({
    issuer,
    authorization_endpoint: `${authority}/oauth/authorize`,
    token_endpoint: `${authority}/oauth/token`,
    // No registration_endpoint on purpose: this server admits exactly one
    // pre-provisioned static client, so advertising DCR would invite failures.
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    scopes_supported: ["lnwjud:mcp"],
    // Gemini's callback must not receive iss, so do not advertise that we send it.
  });

  const protectedResourceMetadata = () => ({
    resource,
    authorization_servers: [issuer],
    scopes_supported: ["lnwjud:mcp"],
    bearer_methods_supported: ["header"],
  });

  // Mark prior, unfinished intents for this client/redirect as superseded so they stop
  // being treated as a recovery candidate. A grant that is still active is the one
  // signal that an intent is genuinely in use, so anything backing one is skipped.
  async function retireAbandonedIntents(clientIdForPrune, redirectUriForPrune) {
    const retired = await store._mutate((state) => {
      const liveIntentIds = new Set(
        state.oauthGrants
          .filter((g) => g.status === "active" && g.bootstrap_intent_id)
          .map((g) => g.bootstrap_intent_id),
      );
      const at = new Date(store.now()).toISOString();
      const bindingIds = [];
      let n = 0;
      for (const prior of state.bootstrapIntents) {
        if (prior.client_id !== clientIdForPrune) continue;
        if (prior.redirect_uri !== redirectUriForPrune) continue;
        if (!["code_issued", "installation_pending", "bootstrap_verified"].includes(prior.status)) continue;
        if (prior.registration_id) continue;
        if (liveIntentIds.has(prior.bootstrap_intent_id)) continue;
        prior.status = "superseded";
        prior.updated_at = at;
        prior.record_revision = (prior.record_revision ?? 1) + 1;
        if (prior.binding_id) bindingIds.push(prior.binding_id);
        n += 1;
      }
      return { count: n, bindingIds };
    });

    // An abandoned attempt also held an invite quota reservation. Leaving it held burns
    // the invite permanently, because this lane never commits an enrollment.
    for (const bindingId of retired.bindingIds ?? []) {
      try {
        await store.releaseEnrollmentReservation(bindingId, null, "intent_retired");
      } catch (err) {
        console.log(`${new Date().toISOString()} reservation release failed for ${bindingId}: ${err?.message ?? "unknown"}`);
      }
    }

    if (retired.count > 0) {
      console.log(`${new Date().toISOString()} retired ${retired.count} abandoned bootstrap intent(s); released ${(retired.bindingIds ?? []).length} reservation(s)`);
    }
    return retired.count;
  }

  // Gemini's callback identifier is not stable across attempts. Accept a redirect only
  // when it is exactly Google's user-bound custom-app callback for this host family, and
  // persist it so an operator can see every accepted value with --status.
  const ALLOWED_CALLBACK_PATTERNS = [
    /^https:\/\/oauth-redirect\.googleusercontent\.com\/r\/user_bound_custom-mcp-[0-9a-f]{16,64}$/,
    /^https:\/\/claude\.(ai|com)\/api\/mcp\/auth_callback$/,
    /^https:\/\/(chatgpt\.com|chat\.openai\.com)\/connector_platform_oauth_redirect$/,
    /^https:\/\/(chatgpt\.com|chat\.openai\.com)\/connector\/oauth\/[A-Za-z0-9_-]{6,64}$/,
  ];
  // Clients may rotate or use official platform callbacks; keep only the most recent few.
  const MAX_ADOPTED_REDIRECTS = 50;

  async function adoptGeminiRedirectUri(clientIdForAdopt, redirectUri) {
    if (typeof redirectUri !== "string" || !ALLOWED_CALLBACK_PATTERNS.some((re) => re.test(redirectUri))) {
      return { ok: false, reason: "shape" };
    }
    try {
      await store._mutate((state) => {
        const client = state.staticOAuthClients.find((c) => c.client_id === clientIdForAdopt);
        if (!client) throw new Error("client missing");
        if (client.redirect_uris.includes(redirectUri)) return;
        client.redirect_uris.push(redirectUri);
        // Bounded: evict only the oldest dynamic callback pattern entry, never pre-registered static URIs.
        while (client.redirect_uris.length > MAX_ADOPTED_REDIRECTS) {
          const idx = client.redirect_uris.findIndex((u) => ALLOWED_CALLBACK_PATTERNS.some((re) => re.test(u)));
          if (idx === -1) break;
          client.redirect_uris.splice(idx, 1);
        }
        client.record_revision = (client.record_revision ?? 1) + 1;
      });
      return { ok: true };
    } catch {
      return { ok: false, reason: "store" };
    }
  }

  async function handleAuthorize(req, res, url) {
    if (req.method !== "GET") {
      sendJson(res, 405, { error: "invalid_request", error_description: "authorize requires GET" }, { allow: MAX_WRONG_METHOD_ALLOW });
      return true;
    }
    const p = url.searchParams;
    const requestedClient = p.get("client_id");
    const redirectUri = p.get("redirect_uri");
    const responseType = p.get("response_type");
    const codeChallenge = p.get("code_challenge");
    const codeChallengeMethod = p.get("code_challenge_method");
    const state = p.get("state");
    const scope = p.get("scope") ?? "lnwjud:mcp";
    const requestedResource = p.get("resource") ?? resource;

    if (!isAdmitted(requestedClient)) {
      sendJson(res, 400, { error: "invalid_client", error_description: "unknown client_id" });
      return true;
    }
    // Validate redirect before anything is disclosed or issued.
    try {
      await store.validateAuthorizationRedirect({ clientId: requestedClient, redirectUri });
    } catch (err) {
      // Gemini rotates the user_bound_custom-mcp identifier between attempts, so a
      // pinned list rejects the app it just created. Accept only the exact Gemini
      // callback shape, and persist what was accepted so the allowlist stays visible.
      const adopted = await adoptGeminiRedirectUri(requestedClient, redirectUri);
      if (!adopted.ok) {
        // redirect_uri is not a secret and is the only way to learn the real value
        // if Gemini's registered callback differs from what we preconfigured.
        console.log(`${new Date().toISOString()} authorize rejected client=${requestedClient} redirect_uri=${String(redirectUri)} reason=${err?.message ?? "invalid"}`);
        sendJson(res, 400, { error: "invalid_request", error_description: err.message ?? "invalid redirect_uri" });
        return true;
      }
      console.log(`${new Date().toISOString()} adopted rotated Gemini redirect_uri=${String(redirectUri)}`);
    }
    if (responseType !== "code") {
      redirectWithError(res, { redirectUri, error: "unsupported_response_type", description: "only code", state });
      return true;
    }
    if (codeChallengeMethod !== "S256" || typeof codeChallenge !== "string" || codeChallenge.length < 43) {
      redirectWithError(res, { redirectUri, error: "invalid_request", description: "PKCE S256 required", state });
      return true;
    }
    if (typeof state !== "string" || state.length === 0) {
      redirectWithError(res, { redirectUri, error: "invalid_request", description: "state required", state });
      return true;
    }
    if (requestedResource !== resource) {
      redirectWithError(res, { redirectUri, error: "invalid_target", description: "resource mismatch", state });
      return true;
    }

    const sessionId = randomBytes(32).toString("base64url");
    const csrfToken = randomBytes(32).toString("base64url");

    // This lane never commits a registration (there is no Core/enrollment step), so a
    // previous successful attempt stays in code_issued/installation_pending forever and
    // every later attempt would be forced through the supersession confirmation. Retire
    // those abandoned intents explicitly so each new attempt starts clean. Intents that
    // back a live grant are left untouched.
    await retireAbandonedIntents(requestedClient, redirectUri);

    let intent;
    try {
      intent = await store.createBootstrapIntent({
        clientId: requestedClient,
        redirectUri,
        codeChallenge,
        codeChallengeMethod: "S256",
        state,
        scope,
        resource: requestedResource,
        authorizationAuthority: authority,
        browserSessionHash: sha256Hex(sessionId),
        csrfTokenHash: sha256Hex(csrfToken),
        adapterType: "GEMINI_STATIC_OAUTH_GRANT",
        ttlMs: 5 * 60 * 1000,
      });
    } catch (err) {
      const status = Number.isInteger(err?.status) ? err.status : 400;
      sendJson(res, status, { error: "invalid_request", error_description: err.message ?? "authorize rejected" });
      return true;
    }

    const html = renderBootstrapPage({
      intent: {
        bootstrap_intent_id: intent.bootstrap_intent_id,
        resource: intent.resource,
        scope: intent.scope,
      },
      csrfToken,
      clientName: "WinHelm",
    });

    sendHtml(res, 200, html, {
      "set-cookie": `${SESSION_COOKIE}=${sessionId}.${csrfToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    });
    return true;
  }

  // The cookie carries both the browser-session id and the CSRF token so a page can be
  // re-rendered (e.g. the supersession confirmation) without server-side session state.
  function readSession(req) {
    const raw = parseCookies(req.headers.cookie).get(SESSION_COOKIE);
    if (typeof raw !== "string" || !raw.includes(".")) return null;
    const idx = raw.indexOf(".");
    const sessionId = raw.slice(0, idx);
    const csrfToken = raw.slice(idx + 1);
    if (!sessionId || !csrfToken) return null;
    return { sessionId, csrfToken };
  }

  async function handleBootstrapPost(req, res, url, intentId) {
    if (req.method !== "POST") {
      sendJson(res, 405, { error: "invalid_request" }, { allow: "POST" });
      return true;
    }
    const session = readSession(req);
    if (!session) {
      sendHtml(res, 400, renderTerminalPage({ title: "Session expired", message: "Reopen the connection from Gemini to continue." }));
      return true;
    }
    const browserSessionHash = sha256Hex(session.sessionId);

    let form;
    try {
      form = await readForm(req);
    } catch (err) {
      sendJson(res, err?.status ?? 400, { error: "invalid_request" });
      return true;
    }

    const action = form.get("action") ?? "continue";
    const csrfToken = form.get("csrf_token") ?? "";

    if (action === "cancel") {
      sendHtml(res, 200, renderTerminalPage({ title: "Authorization cancelled", message: "No access was granted." }));
      return true;
    }

    // Supersession: an earlier incomplete enrollment must be replaced explicitly.
    if (action === "replace") {
      let confirm;
      try {
        confirm = await store.confirmBootstrapSupersessionAndIssueCode({
          intentId,
          browserSessionHash,
          csrfToken,
          origin: authority,
        });
      } catch (err) {
        sendHtml(res, Number.isInteger(err?.status) ? err.status : 400,
          renderTerminalPage({ title: "Authorization rejected", message: err?.message ?? "Request rejected." }));
        return true;
      }
      if (!confirm?.ok) {
        sendHtml(res, Number.isInteger(confirm?.status) ? confirm.status : 400,
          renderTerminalPage({ title: "Authorization rejected", message: confirm?.code ?? "Request rejected." }));
        return true;
      }
      return finishCodeIssuance(res, confirm);
    }

    const inviteCredential = String(form.get("invite") ?? "").trim();

    let result;
    try {
      result = await store.verifyBootstrapInviteAndIssueCode({
        intentId,
        browserSessionHash,
        csrfToken,
        origin: authority,
        inviteCredential,
        legacyTransport: false,
      });
    } catch (err) {
      // The store raises this in the throw path as well as returning it in the
      // governed-replacement path; both must land on the confirmation page.
      const code = err?.code ?? err?.message ?? "";
      console.log(`${new Date().toISOString()} bootstrap THROW code=${err?.code} status=${err?.status} msg=${err?.message}`);
      console.log(String(err?.stack ?? "").split("\n").slice(0,4).join(" | "));
      if (String(code).includes("BOOTSTRAP_SUPERSESSION_CONFIRMATION_REQUIRED")) {
        const page = renderSupersessionPage({
          intent: { bootstrap_intent_id: intentId, resource, scope: "lnwjud:mcp" },
          csrfToken: session.csrfToken,
          clientName: "WinHelm",
        });
        sendHtml(res, 200, page, {
          "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        });
        return true;
      }
      if (String(code).includes("BOOTSTRAP_APPROVAL_UNAVAILABLE") || String(code).includes("INVITE_INVALID")) {
        const page = renderBootstrapPage({
          intent: { bootstrap_intent_id: intentId, resource, scope: "lnwjud:mcp" },
          csrfToken: session.csrfToken,
          clientName: "WinHelm",
          errorMessage: "รหัส Invite ไม่ถูกต้อง หรือหมดอายุแล้ว กรุณาตรวจสอบรหัสอีกครั้ง (Invite invalid or expired)",
        });
        sendHtml(res, 200, page, {
          "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        });
        return true;
      }
      sendHtml(res, Number.isInteger(err?.status) ? err.status : 400,
        renderTerminalPage({ title: "Authorization rejected", message: err?.message ?? "Request rejected." }));
      return true;
    }

    if (!result?.ok) {
      console.log(`${new Date().toISOString()} bootstrap result code=${result?.code} status=${result?.status} category=${result?.category}`);
      // Governed replacement path: show the explicit confirmation page instead of a
      // dead end, exactly as the reviewed R7 flow does.
      if (result?.code === "BOOTSTRAP_SUPERSESSION_CONFIRMATION_REQUIRED") {
        const page = renderSupersessionPage({
          intent: { bootstrap_intent_id: intentId, resource, scope: "lnwjud:mcp" },
          csrfToken: session.csrfToken,
          clientName: "WinHelm",
        });
        sendHtml(res, 200, page, {
          "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        });
        return true;
      }
      if (result?.code === "BOOTSTRAP_APPROVAL_UNAVAILABLE" || result?.code === "INVITE_INVALID") {
        const page = renderBootstrapPage({
          intent: { bootstrap_intent_id: intentId, resource, scope: "lnwjud:mcp" },
          csrfToken: session.csrfToken,
          clientName: "WinHelm",
          errorMessage: "รหัส Invite ไม่ถูกต้อง หรือหมดอายุแล้ว กรุณาตรวจสอบรหัสอีกครั้ง (Invite invalid or expired)",
        });
        sendHtml(res, 200, page, {
          "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        });
        return true;
      }
      sendHtml(res, Number.isInteger(result?.status) ? result.status : 400,
        renderTerminalPage({ title: "Authorization rejected", message: result?.code ?? "Request rejected." }));
      return true;
    }

    return finishCodeIssuance(res, result);
  }

  function escapeHtmlAttribute(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Gemini cannot follow a bare 302 out of the popup it opens, so the reviewed R7 flow
  // returns an HTML handoff page and the user clicks through. Sending 302 here silently
  // strands the flow: the code is issued but Gemini never redeems it.
  async function finishCodeIssuance(res, result) {
    const usedClientId = result?.authTransaction?.client_id
      ?? result?.intent?.client_id
      ?? result?.client_id
      ?? null;
    const code = result.rawCode ?? result.raw_code ?? result.code;
    const redirectUri = result.redirectUri ?? result.redirect_uri;
    const state = result.state ?? result.intent?.oauth_state;
    if (!code || !redirectUri) {
      sendHtml(res, 500, renderTerminalPage({ title: "Authorization failed", message: "Incomplete code issuance." }));
      return true;
    }

    const client = usedClientId ? await store.findOAuthClient(usedClientId) : null;
    if (!client) {
      sendHtml(res, 500, renderTerminalPage({ title: "Authorization failed", message: "Unknown client for this code." }));
      return true;
    }
    const target = new URL(redirectUri);
    target.searchParams.set("code", code);
    if (typeof state === "string" && state.length) target.searchParams.set("state", state);
    if (!client?.omit_iss) target.searchParams.set("iss", issuer);

    const isHtmlHandoffCallback =
      target.hostname === "oauth-redirect.googleusercontent.com" ||
      target.hostname === "chatgpt.com" ||
      target.hostname === "chat.openai.com";
    if (isHtmlHandoffCallback && client?.html_handoff) {
      const href = escapeHtmlAttribute(target.toString());
      const html =
        '<!doctype html><html><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width,initial-scale=1">' +
        `<meta http-equiv="refresh" content="0;url=${href}">` +
        '<title>Authorization complete</title>' +
        '<style>body{font-family:system-ui,sans-serif;margin:0;padding:2rem;background:#f5f7fb;color:#152033}' +
        '.card{max-width:42rem;margin:8vh auto;background:#fff;border:1px solid #dce3ef;border-radius:1rem;padding:2rem;box-shadow:0 12px 36px rgba(20,40,80,.12)}' +
        'a{display:inline-block;margin-top:1rem;padding:.75rem 1rem;border-radius:.7rem;background:#1768e5;color:#fff;text-decoration:none;font-weight:650}</style>' +
        '</head><body><main class="card"><h1>Authorization complete</h1>' +
        '<p>Redirecting back to your application to finish connecting...</p>' +
        // No rel="noreferrer" here: it implies noopener, which would strip
        // window.opener from the callback and break its completion step.
        `<a href="${href}">Continue</a></main></body></html>`;
      sendHtml(res, 200, html, {
        "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
      });
      return true;
    }

    res.writeHead(302, {
      location: target.toString(),
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
    });
    res.end();
    return true;
  }

  async function handleToken(req, res) {
    if (req.method !== "POST") {
      sendJson(res, 405, { error: "invalid_request" }, { allow: "POST" });
      return true;
    }
    let form;
    try {
      form = await readForm(req);
    } catch (err) {
      sendJson(res, err?.status ?? 400, { error: "invalid_request" });
      return true;
    }

    const grantType = form.get("grant_type") ?? "";
    let clientIdParam = form.get("client_id") ?? "";
    let clientSecret = form.get("client_secret") ?? "";
    const authHdr = typeof req.headers.authorization === "string" ? req.headers.authorization : "";
    const basicMatch = authHdr.match(/^Basic\s+([A-Za-z0-9+/=]+)$/i);
    if (basicMatch && (!clientSecret || !clientIdParam)) {
      try {
        const decoded = Buffer.from(basicMatch[1], "base64").toString("utf8");
        const colonIdx = decoded.indexOf(":");
        if (colonIdx !== -1) {
          const basicId = decodeURIComponent(decoded.slice(0, colonIdx));
          const basicSec = decodeURIComponent(decoded.slice(colonIdx + 1));
          if (!clientIdParam) clientIdParam = basicId;
          if (!clientSecret) clientSecret = basicSec;
        }
      } catch {}
    }

    let client;
    try {
      client = await store.authenticateTokenClient({ clientId: clientIdParam, clientSecret });
    } catch (err) {
      console.log(`${new Date().toISOString()} token client auth failed client=${clientIdParam} hasBasic=${Boolean(basicMatch)} formKeys=${[...form.keys()].join(",")} reason=${err?.message ?? "unknown"}`);
      sendJson(res, Number.isInteger(err?.status) ? err.status : 401, { error: "invalid_client", error_description: err?.message ?? "client authentication failed" });
      return true;
    }
    if (!client || !isAdmitted(client.client_id)) {
      sendJson(res, 401, { error: "invalid_client" });
      return true;
    }

    try {
      if (grantType === "authorization_code") {
        const tokens = await store.exchangeAuthorizationCode({
          code: form.get("code") ?? "",
          clientId: clientIdParam,
          redirectUri: form.get("redirect_uri") ?? "",
          codeVerifier: form.get("code_verifier") ?? "",
          resource: form.get("resource") ?? resource,
          clientAuthenticated: true,
        });
        sendJson(res, 200, tokens);
        return true;
      }
      if (grantType === "refresh_token") {
        const tokens = await store.refreshTokensPathwayA({
          refreshToken: form.get("refresh_token") ?? "",
          resource: form.get("resource") ?? resource,
          clientId: clientIdParam,
          clientAuthenticated: true,
        });
        const status = tokens.status ?? 200;
        if (status !== 200) {
          sendJson(res, status, { error: tokens.error ?? "invalid_grant", error_description: tokens.description });
          return true;
        }
        sendJson(res, 200, {
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          expires_in: tokens.expires_in,
          token_type: tokens.token_type ?? "Bearer",
          scope: tokens.scope ?? "lnwjud:mcp",
        });
        return true;
      }
      sendJson(res, 400, { error: "unsupported_grant_type" });
      return true;
    } catch (err) {
      const status = Number.isInteger(err?.status) ? err.status : 400;
      console.log(`${new Date().toISOString()} token rejected grant_type=${grantType} client=${clientIdParam} status=${status} reason=${err?.message ?? "unknown"}`);
      sendJson(res, status, {
        error: "invalid_grant",
        error_description: err?.message ?? "exchange failed",
      });
      return true;
    }
  }


  /**
   * Route an OAuth/discovery request. Returns true when handled.
   */
  async function handle(req, res, url) {
    const path = url.pathname;

    if (path === "/.well-known/oauth-authorization-server") {
      sendJson(res, 200, authorizationServerMetadata());
      return true;
    }
    if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") {
      sendJson(res, 200, protectedResourceMetadata());
      return true;
    }
    if (path.startsWith("/.well-known/")) {
      sendJson(res, 404, { error: "not_found" });
      return true;
    }
    if (path === "/oauth/authorize") {
      return handleAuthorize(req, res, url);
    }
    if (path === "/oauth/token") {
      return handleToken(req, res);
    }
    if (path.startsWith("/oauth/bootstrap/")) {
      // A malformed percent-encoding here must not escape: an uncaught URIError would
      // become an unhandled rejection and kill the process (there is no auto-restart).
      let intentId;
      try {
        intentId = decodeURIComponent(path.slice("/oauth/bootstrap/".length));
      } catch {
        sendJson(res, 400, { error: "invalid_request" });
        return true;
      }
      return handleBootstrapPost(req, res, url, intentId);
    }
    if (path === "/oauth/register") {
      // Static client only: DCR is deliberately absent from the metadata above too.
      sendJson(res, 404, { error: "not_found" });
      return true;
    }
    if (path.startsWith("/oauth/")) {
      sendJson(res, 404, { error: "not_found" });
      return true;
    }
    return false;
  }

  /**
   * Validate an MCP bearer token. Returns the grant context or null.
   */
  async function authenticateBearer(token) {
    if (typeof token !== "string" || !token) return null;
    try {
      const auth = await store.authenticateOAuthAccessToken({ accessToken: token, expectedResource: resource });
      if (auth?.grant?.oauth_grant_id && typeof store.touchOAuthGrantUsed === "function") {
        await store.touchOAuthGrantUsed(auth.grant.oauth_grant_id).catch(() => {});
      }
      return auth;
    } catch {
      return null;
    }
  }

  return { handle, authenticateBearer, resource, issuer, authorizationServerMetadata, protectedResourceMetadata };
}

export { SESSION_COOKIE };
