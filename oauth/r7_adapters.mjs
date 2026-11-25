import { generateStaticProof } from "./r7_store.mjs";

export const ADAPTER_HEADER_VALUES = Object.freeze({
  "cursor-static": "CURSOR_UNIQUE_STATIC_HEADER",
  "claude-static": "CLAUDE_UNIQUE_FIXED_HEADER",
  "chatgpt-oauth": "CHATGPT_OAUTH_DCR_GRANT",
  "claude-oauth": "CLAUDE_OAUTH_DCR_GRANT",
});

export function headerValue(req, name) {
  const raw = req.headers[String(name).toLowerCase()];
  if (Array.isArray(raw)) return raw[0] ?? null;
  return typeof raw === "string" ? raw : null;
}

export function parseBearer(value) {
  if (typeof value !== "string") return null;
  const match = /^Bearer\s+(.+)$/i.exec(value.trim());
  return match ? match[1] : null;
}

export function parseR7Auth(req) {
  const adapterHeader = headerValue(req, "x-winhelm-binding-adapter");
  const adapterType = ADAPTER_HEADER_VALUES[adapterHeader] ?? null;
  const bearerToken = parseBearer(headerValue(req, "authorization"));
  const inviteCredential =
    headerValue(req, "x-winhelm-registration-invite") ??
    bearerToken;
  const staticProof = headerValue(req, "x-winhelm-installation-proof");
  const generationRaw = headerValue(req, "x-winhelm-credential-generation");
  const generation = generationRaw && /^[0-9]+$/.test(generationRaw) ? Number(generationRaw) : null;

  return {
    adapterType,
    inviteCredential,
    staticProof,
    generation,
  };
}

export function staticAdapterCapabilities(adapterType) {
  if (adapterType === "CURSOR_UNIQUE_STATIC_HEADER") {
    return {
      fresh_reinstall_boundary: "PASS",
      refresh_persistence: "PASS",
      binding_rotation_supported: "PASS",
      binding_revocation_supported: "PASS",
      lost_response_recovery_supported: "PASS",
      migration_handoff_supported: "PASS",
    };
  }
  if (adapterType === "CLAUDE_UNIQUE_FIXED_HEADER") {
    return {
      fresh_reinstall_boundary: "UNKNOWN",
      refresh_persistence: "PASS",
      binding_rotation_supported: "PASS",
      binding_revocation_supported: "PASS",
      lost_response_recovery_supported: "PASS",
      migration_handoff_supported: "PASS",
    };
  }
  return {
    fresh_reinstall_boundary: "UNKNOWN",
    refresh_persistence: "UNKNOWN",
    binding_rotation_supported: "UNKNOWN",
    binding_revocation_supported: "UNKNOWN",
    lost_response_recovery_supported: "UNKNOWN",
    migration_handoff_supported: "UNKNOWN",
  };
}

export function provisionStaticProof() {
  return generateStaticProof();
}

export function requirePublicAdapter(adapterType) {
  if (!adapterType) {
    const error = new Error("Binding adapter required");
    error.code = "INSTALLATION_BINDING_REQUIRED";
    error.status = 401;
    throw error;
  }
  if (adapterType === "CHATGPT_OAUTH_DCR_GRANT" || adapterType === "CLAUDE_OAUTH_DCR_GRANT") {
    const error = new Error("OAuth adapter is capability-gated pending isolated lifecycle qualification");
    error.code = "INSTALLATION_BINDING_CAPABILITY_UNVERIFIED";
    error.status = 503;
    throw error;
  }
  return adapterType;
}
