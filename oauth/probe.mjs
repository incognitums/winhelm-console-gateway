// Feasibility probe: prove the extracted OAuth cluster works with no WinHelm/Core
// dependency at all. Read-only apart from a throwaway store under the OS temp dir.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  RegistrationStore,
  ADAPTER_TYPES,
  generateInviteCredential,
  defaultR7StorePath,
} from "./r7_store.mjs";
import { requirePublicAdapter, staticAdapterCapabilities } from "./r7_adapters.mjs";
import { verifyPkce, base64UrlSha256, matchesRedirectUri } from "./r7_oauth.mjs";
import { renderBootstrapPage } from "./r7_authorization_page.mjs";

const results = [];
const check = (name, ok, detail = "") => results.push({ name, ok: !!ok, detail });

// 1. store constructs from scratch with no pre-existing state
const dir = mkdtempSync(path.join(tmpdir(), "lnwjud-oauth-probe-"));
const storePath = path.join(dir, "store.json");
const store = new RegistrationStore({ storePath });
check("store constructs", store != null, storePath);

const snap = store.snapshot();
check("store snapshot is an object", snap && typeof snap === "object");
check("no Core fields in snapshot", !JSON.stringify(snap).match(/core|backendHost|worker/i));

// 2. static confidential client can be created (the Gemini shape)
const client = await store.ensureStaticOAuthClient({
  clientId: "lnwjud-static-1",
  clientName: "lnwjud gemini probe",
  clientSecret: "probe-secret-value-that-is-long-enough-0123456789",
  redirectUris: ["https://oauth-redirect.googleusercontent.com/r/probe"],
});
check("static client created", client != null, `type=${client?.client_type} auth=${client?.token_endpoint_auth_method}`);

const found = await store.findOAuthClient("lnwjud-static-1");
check("static client readable", found?.client_id === "lnwjud-static-1");

// 3. client_secret authentication path works
const authed = await store.authenticateTokenClient({
  clientId: "lnwjud-static-1",
  clientSecret: "probe-secret-value-that-is-long-enough-0123456789",
});
check("client_secret_post accepted", authed != null);

let rejected = false;
try {
  await store.authenticateTokenClient({ clientId: "lnwjud-static-1", clientSecret: "wrong" });
} catch {
  rejected = true;
}
check("wrong secret rejected", rejected);

// 4. PKCE S256 primitives behave
const verifier = "a".repeat(43);
const challenge = base64UrlSha256(verifier);
check("PKCE S256 verify", verifyPkce(verifier, challenge, "S256") === true);
check("PKCE S256 rejects wrong verifier", verifyPkce("b".repeat(43), challenge, "S256") === false);

// 5. redirect URI matching
check(
  "redirect match",
  matchesRedirectUri(["https://oauth-redirect.googleusercontent.com/r/probe"], "https://oauth-redirect.googleusercontent.com/r/probe") === true,
);
check(
  "redirect mismatch blocked",
  matchesRedirectUri(["https://oauth-redirect.googleusercontent.com/r/probe"], "https://evil.example/cb") === false,
);

// 6. adapter whitelist (the only WinHelm-named seam left)
check("adapter types exist", ADAPTER_TYPES.length > 0, ADAPTER_TYPES.join(","));
const gemini = ADAPTER_TYPES.find((t) => String(t).includes("GEMINI"));
check("GEMINI adapter present", !!gemini, String(gemini));
if (gemini) {
  check("requirePublicAdapter accepts GEMINI", requirePublicAdapter(gemini) === gemini);
  const caps = staticAdapterCapabilities(gemini);
  check("staticAdapterCapabilities returns object", caps && typeof caps === "object");
}

// 7. invite credential generator (bootstrap flow input)
const invite = generateInviteCredential();
check("invite credential generated", typeof invite === "string" && invite.length > 20, `len=${invite.length}`);

// 8. HTML page renderer is standalone
const html = renderBootstrapPage({
  intent: {
    bootstrap_intent_id: "intent-probe",
    resource: "https://example.tailnet.ts.net/mcp",
    scope: "winhelm:mcp",
  },
  csrfToken: "csrf-probe",
  styleNonce: "nonce-probe",
});
check("bootstrap page renders", typeof html === "string" && html.includes("<form"), `len=${html.length}`);

// 9. default path is no longer a WinHelm path
check("default path rebranded", defaultR7StorePath().includes(".lnwjud"), defaultR7StorePath());

for (const r of results) {
  console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name.padEnd(38)} ${r.detail}`);
}
const failed = results.filter((r) => !r.ok).length;
console.log(`\nRESULT: pass=${results.length - failed} fail=${failed}`);
process.exitCode = failed === 0 ? 0 : 1;
