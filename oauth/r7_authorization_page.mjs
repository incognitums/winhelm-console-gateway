function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function normalizeRedirectOrigin(redirectUri) {
  if (typeof redirectUri !== "string" || !redirectUri.trim()) {
    throw new Error("MALFORMED_REDIRECT_URI");
  }
  let parsed;
  try {
    parsed = new URL(redirectUri);
  } catch {
    throw new Error("MALFORMED_REDIRECT_URI");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("MALFORMED_REDIRECT_URI");
  }
  const origin = parsed.origin;
  if (!origin || origin === "null" || /[\s;,'"]/.test(origin)) {
    throw new Error("MALFORMED_REDIRECT_URI");
  }
  return origin;
}

export function bootstrapSecurityHeaders(styleNonce, { redirectUri } = {}) {
  let formAction = "form-action 'self'";
  if (redirectUri !== undefined && redirectUri !== null) {
    const origin = normalizeRedirectOrigin(redirectUri);
    formAction = `form-action 'self' ${origin}`;
  }
  return {
    "cache-control": "no-store, max-age=0",
    pragma: "no-cache",
    "referrer-policy": "same-origin",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": [
      "default-src 'none'",
      `style-src 'nonce-${styleNonce}'`,
      "script-src 'none'",
      formAction,
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "object-src 'none'",
    ].join("; "),
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  };
}

function shellStyles() {
  return `
:root{
  color-scheme:light;
  --ink:#10213a;
  --muted:#60708a;
  --line:#dbe5f2;
  --line-strong:#c8d8ec;
  --panel:#ffffff;
  --panel-soft:#f5f8fc;
  --accent:#2f7df6;
  --accent-strong:#1768e5;
  --accent-soft:#eaf2ff;
  --danger:#b42318;
  --danger-bg:#fff3f2;
  --danger-line:#fecdca;
  --shadow:0 24px 70px rgba(29,65,112,.14),0 4px 14px rgba(29,65,112,.06);
}
*{box-sizing:border-box}
html,body{min-height:100%}
body{
  margin:0;
  color:var(--ink);
  background:
    radial-gradient(circle at 18% 12%,rgba(83,148,255,.14),transparent 30rem),
    radial-gradient(circle at 86% 82%,rgba(104,160,255,.12),transparent 32rem),
    linear-gradient(180deg,#f8fbff 0%,#f1f6fc 100%);
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  line-height:1.5;
  -webkit-font-smoothing:antialiased;
}
body::before,
body::after{
  content:"";
  position:fixed;
  z-index:0;
  left:-10vw;
  right:-10vw;
  height:22rem;
  border-radius:50%;
  pointer-events:none;
}
body::before{
  bottom:-15rem;
  background:rgba(76,137,232,.055);
  transform:rotate(4deg);
}
body::after{
  bottom:-18rem;
  background:rgba(76,137,232,.045);
  transform:rotate(-5deg);
}
.page{
  position:relative;
  z-index:1;
  min-height:100vh;
  display:grid;
  place-items:center;
  padding:2rem 1rem;
}
.card{
  width:min(100%,44rem);
  background:rgba(255,255,255,.96);
  border:1px solid rgba(206,220,238,.9);
  border-radius:1.5rem;
  box-shadow:var(--shadow);
  padding:2.25rem;
  backdrop-filter:blur(14px);
}
.brand{
  display:flex;
  flex-direction:column;
  align-items:center;
  text-align:center;
  margin-bottom:1.5rem;
}
.emblem{
  width:5.25rem;
  height:5.25rem;
  display:grid;
  place-items:center;
  margin-bottom:1rem;
  border-radius:1.6rem;
  color:#fff;
  background:linear-gradient(145deg,#67a2ff,#216fe9);
  box-shadow:0 12px 30px rgba(47,125,246,.25),inset 0 1px 0 rgba(255,255,255,.45);
  font-size:2.5rem;
  font-weight:700;
  letter-spacing:-.08em;
}
h1{
  margin:0;
  font-size:clamp(1.85rem,4vw,2.45rem);
  line-height:1.12;
  letter-spacing:-.035em;
}
.subtitle{
  margin:.75rem 0 0;
  color:var(--muted);
  font-size:1rem;
}
.details{
  display:grid;
  gap:.2rem;
  margin:1.5rem 0;
  padding:1rem 1.1rem;
  border:1px solid #e6edf7;
  border-radius:1rem;
  background:linear-gradient(180deg,#f8faff,#f4f7fb);
}
.detail{
  display:grid;
  grid-template-columns:7.25rem minmax(0,1fr);
  gap:.75rem;
  align-items:start;
  padding:.55rem .35rem;
}
.detail-label{
  display:flex;
  align-items:center;
  gap:.55rem;
  color:var(--muted);
  font-weight:650;
}
.detail-icon{
  width:1.8rem;
  height:1.8rem;
  display:grid;
  place-items:center;
  flex:0 0 auto;
  border-radius:.55rem;
  color:var(--accent-strong);
  background:var(--accent-soft);
  font-size:.9rem;
  font-weight:800;
}
.detail-value{
  min-width:0;
  color:var(--ink);
  font-weight:650;
  overflow-wrap:anywhere;
}
.detail-value.meta{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:.92rem;font-weight:550}
form{margin:0}
.field-label{
  display:block;
  margin:0 0 .55rem;
  font-size:.95rem;
  font-weight:750;
}
.secret-wrap{
  position:relative;
}
input{
  display:block;
  width:100%;
  height:3.55rem;
  padding:0 3.15rem 0 1rem;
  border:1px solid var(--line-strong);
  border-radius:.8rem;
  outline:none;
  background:#fff;
  color:var(--ink);
  font:inherit;
  box-shadow:0 1px 2px rgba(15,35,62,.03);
  transition:border-color .16s ease,box-shadow .16s ease,background .16s ease;
}
input:focus{
  border-color:#6aa3ff;
  box-shadow:0 0 0 4px rgba(47,125,246,.13);
  background:#fff;
}
.secret-icon{
  position:absolute;
  right:1rem;
  top:50%;
  transform:translateY(-50%);
  color:#6b7d95;
  font-size:1.15rem;
  pointer-events:none;
}
.actions{
  display:grid;
  gap:.75rem;
  margin-top:1rem;
}
button{
  display:flex;
  width:100%;
  min-height:3.35rem;
  align-items:center;
  justify-content:center;
  gap:.65rem;
  border-radius:.8rem;
  border:1px solid transparent;
  cursor:pointer;
  font:inherit;
  font-weight:750;
  transition:transform .12s ease,box-shadow .16s ease,background .16s ease,border-color .16s ease;
}
button:hover{transform:translateY(-1px)}
button:active{transform:translateY(0)}
.primary{
  color:#fff;
  background:linear-gradient(180deg,#3688ff,#2172ed);
  border-color:#1f6ee4;
  box-shadow:0 8px 20px rgba(47,125,246,.24);
}
.primary:hover{background:linear-gradient(180deg,#2d80f7,#1768e5)}
.secondary{
  color:#41516a;
  background:#fff;
  border-color:var(--line);
}
.secondary:hover{background:#f7f9fc;border-color:#c9d5e5}
.error{
  margin:0 0 1rem;
  padding:.8rem .95rem;
  border:1px solid var(--danger-line);
  border-radius:.75rem;
  color:var(--danger);
  background:var(--danger-bg);
  font-weight:700;
}
.note{
  margin:1rem 0 0;
  color:#7a899f;
  text-align:center;
  font-size:.84rem;
}
@media (max-width:640px){
  .page{padding:1rem .75rem}
  .card{padding:1.35rem;border-radius:1.1rem}
  .emblem{width:4.4rem;height:4.4rem;border-radius:1.35rem;font-size:2.1rem}
  .detail{grid-template-columns:1fr;gap:.15rem}
  .details{padding:.75rem}
}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{scroll-behavior:auto!important;transition:none!important}
}
`;
}

function brandMarkup({ title, subtitle }) {
  return `<header class="brand">
<div class="emblem" aria-hidden="true">L</div>
<h1>${title}</h1>
<p class="subtitle">${subtitle}</p>
</header>`;
}

export function renderBootstrapPage({
  intent,
  csrfToken,
  styleNonce,
  clientName = "OAuth client",
  errorMessage = null,
}) {
  const intentId = escapeHtml(intent.bootstrap_intent_id);
  const csrf = escapeHtml(csrfToken);
  const client = escapeHtml(clientName);
  const resource = escapeHtml(intent.resource);
  const scope = escapeHtml(intent.scope);
  const message = errorMessage
    ? `<p role="alert" class="error">${escapeHtml(errorMessage)}</p>`
    : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>Authorize lnwjud</title>
<style nonce="${escapeHtml(styleNonce)}">${shellStyles()}</style>
</head>
<body>
<div class="page">
<main class="card">
${brandMarkup({
  title: "Connect to lnwjud",
  subtitle: `Enter the registration invite to securely connect ${client} to lnwjud.`,
})}
<section class="details" aria-label="Connection details">
<div class="detail"><div class="detail-label"><span class="detail-icon" aria-hidden="true">C</span>Client</div><div class="detail-value">${client}</div></div>
<div class="detail"><div class="detail-label"><span class="detail-icon" aria-hidden="true">R</span>Resource</div><div class="detail-value meta">${resource}</div></div>
<div class="detail"><div class="detail-label"><span class="detail-icon" aria-hidden="true">S</span>Scope</div><div class="detail-value meta">${scope}</div></div>
</section>
${message}
<form method="post" action="/oauth/bootstrap/${intentId}">
<input type="hidden" name="csrf_token" value="${csrf}">
<label class="field-label" for="invite">Registration invite</label>
<div class="secret-wrap">
<input id="invite" name="invite" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" required maxlength="1024" autofocus>
<span class="secret-icon" aria-hidden="true">⌁</span>
</div>
<div class="actions">
<button class="primary" type="submit" name="action" value="continue"><span>Continue</span><span aria-hidden="true">→</span></button>
<button class="secondary" type="submit" name="action" value="cancel" formnovalidate>Cancel</button>
</div>
</form>
<p class="note">Your registration invite is used only to authorize this installation.</p>
</main>
</div>
</body>
</html>`;
}

export function renderSupersessionPage({
  intent,
  csrfToken,
  styleNonce,
  clientName = "OAuth client",
}) {
  const intentId = escapeHtml(intent.bootstrap_intent_id);
  const csrf = escapeHtml(csrfToken);
  const client = escapeHtml(clientName);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>Replace incomplete authorization</title>
<style nonce="${escapeHtml(styleNonce)}">${shellStyles()}</style>
</head>
<body>
<div class="page">
<main class="card">
${brandMarkup({
  title: "Replace incomplete authorization?",
  subtitle: `A previous authorization for ${client} is incomplete.`,
})}
<section class="details" aria-label="Authorization status">
<div class="detail"><div class="detail-label"><span class="detail-icon" aria-hidden="true">C</span>Client</div><div class="detail-value">${client}</div></div>
<div class="detail"><div class="detail-label"><span class="detail-icon" aria-hidden="true">!</span>Status</div><div class="detail-value">Incomplete authorization detected</div></div>
</section>
<p class="supporting">Replace the incomplete authorization with this request?</p>
<form method="post" action="/oauth/bootstrap/${intentId}">
<input type="hidden" name="csrf_token" value="${csrf}">
<div class="actions">
<button class="primary" type="submit" name="action" value="replace">Replace incomplete authorization</button>
<button class="secondary" type="submit" name="action" value="cancel">Cancel</button>
</div>
</form>
</main>
</div>
</body>
</html>`;
}

export function renderTerminalPage({ title, message }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title></head><body><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></main></body></html>`;
}

export const _test = { escapeHtml, normalizeRedirectOrigin };