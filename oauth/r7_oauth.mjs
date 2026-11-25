import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import net from "node:net";

export const DCR_WHITELIST_PROPERTIES = Object.freeze([
  "client_name",
  "grant_types",
  "redirect_uris",
  "response_types",
  "scope",
  "software_id",
  "software_version",
  "token_endpoint_auth_method",
]);

export const ALLOWED_CUSTOM_SCHEMES = Object.freeze(["claude-desktop"]);

export function sha256Hex(value) {
  return createHash("sha256").update(String(value), "utf8").digest("hex").toUpperCase();
}

export function base64UrlSha256(value) {
  return createHash("sha256").update(String(value), "utf8").digest("base64url");
}

export function safeEqualHex(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

export function safeEqualBase64Url(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

export function normalizeRedirectUri(rawUri) {
  if (typeof rawUri !== "string" || rawUri.length === 0) return null;
  try {
    const parsed = new URL(rawUri);
    const scheme = parsed.protocol.toLowerCase();

    // Check Class C (custom scheme)
    if (ALLOWED_CUSTOM_SCHEMES.includes(scheme.replace(/:$/, ""))) {
      return parsed.href;
    }

    const host = parsed.hostname.toLowerCase();
    const port = parsed.port;

    // Normalize default ports
    let effectivePort = port;
    if ((scheme === "https:" && port === "443") || (scheme === "http:" && port === "80")) {
      effectivePort = "";
    }

    const portPart = effectivePort ? `:${effectivePort}` : "";
    return `${scheme}//${host}${portPart}${parsed.pathname}${parsed.search}`;
  } catch {
    return null;
  }
}

export function classifyRedirectUri(rawUri) {
  if (typeof rawUri !== "string") return { valid: false, error: "Invalid URI string" };
  const normalized = normalizeRedirectUri(rawUri);
  if (!normalized) return { valid: false, error: "Malformed redirect URI" };

  try {
    const parsed = new URL(normalized);
    const scheme = parsed.protocol.toLowerCase();
    const bareScheme = scheme.replace(/:$/, "");

    // Check localhost ban (RFC 8252 §7.3)
    if (parsed.hostname.toLowerCase() === "localhost") {
      return { valid: false, error: "Redirect URI with localhost is strictly prohibited; use 127.0.0.1 or [::1]" };
    }

    // Class C: Custom scheme
    if (ALLOWED_CUSTOM_SCHEMES.includes(bareScheme)) {
      return { valid: true, class: "C", uri: normalized };
    }

    // Class B: Native Loopback
    if (scheme === "http:") {
      const hostname = parsed.hostname.toLowerCase();
      if (hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1") {
        return { valid: true, class: "B", uri: normalized };
      }
      return { valid: false, error: "HTTP redirect URI is only permitted for literal loopback IP (127.0.0.1 or [::1])" };
    }

    // Class A: Remote Web Client
    if (scheme === "https:") {
      const hostname = parsed.hostname.toLowerCase();
      // Must be FQDN: not an IP address, not localhost
      if (net.isIP(hostname.replace(/^\[|\]$/g, "")) !== 0) {
        return { valid: false, error: "HTTPS redirect URI must use FQDN, not IP address" };
      }
      if (parsed.port && parsed.port !== "443") {
        return { valid: false, error: "HTTPS redirect URI with non-standard port is prohibited" };
      }
      return { valid: true, class: "A", uri: normalized };
    }

    return { valid: false, error: `Unsupported redirect URI scheme ${scheme}` };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

export function validateRedirectUris(uris) {
  if (!Array.isArray(uris) || uris.length === 0) {
    return { ok: false, error: "redirect_uris must be a non-empty array" };
  }
  for (const uri of uris) {
    const res = classifyRedirectUri(uri);
    if (!res.valid) {
      return { ok: false, error: res.error };
    }
  }
  return { ok: true };
}

export function matchesRedirectUri(registeredUris, requestedUri) {
  if (!Array.isArray(registeredUris) || typeof requestedUri !== "string") return false;
  const reqClass = classifyRedirectUri(requestedUri);
  if (!reqClass.valid) return false;

  const reqParsed = new URL(requestedUri);

  for (const reg of registeredUris) {
    const regClass = classifyRedirectUri(reg);
    if (!regClass.valid) continue;

    if (regClass.class === "B" && reqClass.class === "B") {
      // Loopback dynamic port matching (RFC 8252 §7.3): ignore port
      const regParsed = new URL(regClass.uri);
      const regHost = regParsed.hostname.toLowerCase();
      const reqHost = reqParsed.hostname.toLowerCase();
      if (
        regParsed.protocol.toLowerCase() === reqParsed.protocol.toLowerCase() &&
        (regHost === reqHost || (regHost === "[::1]" && reqHost === "::1") || (regHost === "::1" && reqHost === "[::1]")) &&
        regParsed.pathname === reqParsed.pathname
      ) {
        return true;
      }
    } else {
      // Class A or C: exact byte-for-byte / normalized match
      if (regClass.uri === reqClass.uri) {
        return true;
      }
    }
  }

  return false;
}

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) serialization for DCR payload.
 */
export function canonicalizeDcrPayload(body) {
  if (!body || typeof body !== "object") return "{}";

  const extracted = {};

  for (const prop of DCR_WHITELIST_PROPERTIES) {
    if (!Object.prototype.hasOwnProperty.call(body, prop)) continue;
    const val = body[prop];
    if (val === undefined || val === null) continue;

    if (prop === "redirect_uris" && Array.isArray(val)) {
      // Normalize each URI then sort ascending Unicode
      const normalized = val
        .map((u) => normalizeRedirectUri(u))
        .filter((u) => typeof u === "string");
      normalized.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      extracted[prop] = normalized;
    } else if (Array.isArray(val)) {
      // Sort string arrays
      const copy = [...val].map(String);
      copy.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      extracted[prop] = copy;
    } else if (typeof val === "string" || typeof val === "number" || typeof val === "boolean") {
      extracted[prop] = val;
    }
  }

  // Serialize sorted keys (UTF-16 code unit order) with zero whitespace
  const keys = Object.keys(extracted).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const parts = [];
  for (const k of keys) {
    parts.push(`${JSON.stringify(k)}:${JSON.stringify(extracted[k])}`);
  }
  return `{${parts.join(",")}}`;
}

export function computePayloadHash(canonicalJson) {
  return sha256Hex(canonicalJson);
}

export function verifyPkce(codeVerifier, codeChallenge, method = "S256") {
  if (typeof codeVerifier !== "string" || typeof codeChallenge !== "string") return false;
  if (method !== "S256") return false;
  const computed = base64UrlSha256(codeVerifier);
  return safeEqualBase64Url(computed, codeChallenge);
}

export function deriveGrantIdentityKey(oauthGrantId, enrollmentTxId) {
  const input = `WINHELM_R7_OAUTH_GRANT_V1:${oauthGrantId}:${enrollmentTxId}`;
  const hash = sha256Hex(input);
  return "whr7gk_" + hash.slice(0, 40).toLowerCase();
}

export function canonicalizeBootstrapScope(scope) {
  if (typeof scope !== "string") return "";
  const parts = scope.trim().split(/\s+/).filter(Boolean);
  return [...new Set(parts)].sort().join(" ");
}

export function computeBootstrapRequestFingerprint({
  clientId,
  redirectUri,
  authorizationAuthority,
  resource,
  scope,
  responseType = "code",
  codeChallenge,
  codeChallengeMethod = "S256",
  state,
}) {
  const canonicalScope = canonicalizeBootstrapScope(scope);
  const input = [
    "WINHELM_R7_BOOTSTRAP_INTENT_V1",
    String(clientId ?? ""),
    String(redirectUri ?? ""),
    String(authorizationAuthority ?? ""),
    String(resource ?? ""),
    canonicalScope,
    String(responseType ?? ""),
    String(codeChallenge ?? ""),
    String(codeChallengeMethod ?? ""),
    sha256Hex(String(state ?? "")),
  ].join("\n");
  return sha256Hex(input);
}
