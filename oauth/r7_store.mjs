import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  createHash,
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import {
  canonicalizeDcrPayload,
  computePayloadHash,
  validateRedirectUris,
  matchesRedirectUri,
  verifyPkce,
  deriveGrantIdentityKey,
  sha256Hex,
  canonicalizeBootstrapScope,
  computeBootstrapRequestFingerprint,
} from "./r7_oauth.mjs";

export const R7_SCHEMA_VERSION = 4;
export const INVITE_PREFIX = "whr7i_";
export const STATIC_PROOF_PREFIX = "whr7p_";
export const ADAPTER_TYPES = Object.freeze([
  "CHATGPT_OAUTH_DCR_GRANT",
  "GEMINI_STATIC_OAUTH_GRANT",
  "CLAUDE_OAUTH_DCR_GRANT",
  "CLAUDE_UNIQUE_FIXED_HEADER",
  "CURSOR_UNIQUE_STATIC_HEADER",
]);
export const BINDING_STATES = Object.freeze([
  "provisional",
  "active",
  "rotating",
  "revoked",
  "disabled",
  "migration_unbound",
  "expired_cleanup",
]);
export const CAPABILITY_STATES = Object.freeze(["PASS", "FAIL", "UNKNOWN"]);

const DEFAULT_CAPABILITIES = Object.freeze({
  fresh_reinstall_boundary: "UNKNOWN",
  refresh_persistence: "UNKNOWN",
  binding_rotation_supported: "UNKNOWN",
  binding_revocation_supported: "UNKNOWN",
  lost_response_recovery_supported: "UNKNOWN",
  migration_handoff_supported: "UNKNOWN",
});

function nowIso(now = Date.now()) {
  return new Date(now).toISOString();
}

function clone(value) {
  return structuredClone(value);
}

function sha256(value) {
  return createHash("sha256").update(String(value), "utf8").digest("hex").toUpperCase();
}

function fingerprint(value) {
  return sha256(value).slice(0, 12);
}

function safeEqualHex(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function scryptVerifier(secret, salt = randomBytes(16).toString("base64url")) {
  const digest = scryptSync(String(secret), salt, 32).toString("base64url");
  return `scrypt$${salt}$${digest}`;
}

function verifyScrypt(secret, verifier) {
  if (typeof verifier !== "string") return false;
  const parts = verifier.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const digest = scryptSync(String(secret), parts[1], 32).toString("base64url");
  return safeEqualHex(digest, parts[2]);
}

function makeError(code, message = code, status = 409) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  return error;
}

const OAUTH_ACTIVATION_BLOCKING_STATES = new Set(["initializing", "committing", "uncertain"]);
const OAUTH_ACTIVATION_TERMINAL_STATES = new Set(["committed", "released", "expired"]);

function reservationLifecycleState(reservation) {
  return reservation?.status ?? reservation?.state ?? null;
}

function evaluateBootstrapSupersession(store, prior, invite) {
  const reservation = store.registrationReservations.find((r) =>
    r.reservation_id === prior?.reservation_id &&
    r.bootstrap_intent_id === prior?.bootstrap_intent_id &&
    r.enrollment_tx_id === prior?.enrollment_tx_id &&
    r.binding_id === prior?.binding_id &&
    r.registration_invite_id === prior?.registration_invite_id &&
    r.quota_epoch === invite?.quota_epoch
  );
  const enrollment = store.enrollmentTransactions.find((e) =>
    e.enrollment_tx_id === prior?.enrollment_tx_id &&
    e.bootstrap_intent_id === prior?.bootstrap_intent_id &&
    e.binding_id === prior?.binding_id &&
    e.reservation_id === prior?.reservation_id
  );
  const binding = store.installationBindings.find((b) =>
    b.binding_id === prior?.binding_id &&
    b.bootstrap_intent_id === prior?.bootstrap_intent_id &&
    b.enrollment_tx_id === prior?.enrollment_tx_id &&
    b.registration_invite_id === prior?.registration_invite_id &&
    b.binding_state === "provisional" &&
    b.registration_id === null
  );
  const authorization = prior?.authorization_transaction_id
    ? store.authorizationTransactions.find((a) =>
        a.auth_transaction_id === prior.authorization_transaction_id &&
        a.bootstrap_intent_id === prior.bootstrap_intent_id &&
        a.enrollment_tx_id === prior.enrollment_tx_id &&
        a.client_id === prior.client_id)
    : null;
  const grant = prior?.oauth_grant_id
    ? store.oauthGrants.find((g) =>
        g.oauth_grant_id === prior.oauth_grant_id &&
        g.bootstrap_intent_id === prior.bootstrap_intent_id &&
        g.binding_id === prior.binding_id &&
        g.enrollment_tx_id === prior.enrollment_tx_id &&
        g.client_id === prior.client_id)
    : null;

  const state = reservationLifecycleState(reservation);
  const activationStarted = Boolean(reservation?.activation_attempt_id) ||
    OAUTH_ACTIVATION_BLOCKING_STATES.has(state) ||
    state === "committed";
  const exactLineage = Boolean(reservation && enrollment && binding);
  const preInitializeReservation = exactLineage && state === "reserved" && !activationStarted;
  const safeCode = preInitializeReservation &&
    prior?.status === "code_issued" &&
    authorization?.status === "code_issued";
  const safeGrant = preInitializeReservation &&
    prior?.status === "installation_pending" &&
    grant?.status === "active" &&
    grant.last_used_at === null;

  return {
    safe: Boolean(safeCode || safeGrant),
    safeCode: Boolean(safeCode),
    safeGrant: Boolean(safeGrant),
    exactLineage,
    activationStarted,
    reservation,
    enrollment,
    binding,
    authorization,
    grant,
  };
}

const OAUTH_ACTIVATION_ATTEMPT_ID_PATTERN =
  /^whr7act_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function resolveOAuthActivationLineage(store, {
  bindingId,
  oauthGrantId,
  bootstrapIntentId,
  enrollmentTxId,
  reservationId,
  quotaEpoch = undefined,
} = {}) {
  const required = { bindingId, oauthGrantId, bootstrapIntentId, enrollmentTxId, reservationId };
  for (const [name, value] of Object.entries(required)) {
    if (typeof value !== "string" || value.length === 0) {
      throw makeError("OAUTH_ACTIVATION_LINEAGE_INVALID", `Missing ${name}`, 409);
    }
  }
  const binding = store.installationBindings.find((b) => b.binding_id === bindingId);
  const grant = store.oauthGrants.find((g) => g.oauth_grant_id === oauthGrantId);
  const intent = store.bootstrapIntents.find((i) => i.bootstrap_intent_id === bootstrapIntentId);
  const enrollment = store.enrollmentTransactions.find((e) => e.enrollment_tx_id === enrollmentTxId);
  const reservation = store.registrationReservations.find((r) => r.reservation_id === reservationId);
  if (!binding || !grant || !intent || !enrollment || !reservation) {
    throw makeError("OAUTH_ACTIVATION_LINEAGE_INVALID", "Activation lineage record missing", 409);
  }
  const invite = store.registrationInvites.find((i) => i.registration_invite_id === reservation.registration_invite_id);
  if (!invite ||
      binding.bootstrap_intent_id !== bootstrapIntentId ||
      binding.enrollment_tx_id !== enrollmentTxId ||
      binding.registration_invite_id !== reservation.registration_invite_id ||
      grant.bootstrap_intent_id !== bootstrapIntentId ||
      grant.binding_id !== bindingId ||
      grant.enrollment_tx_id !== enrollmentTxId ||
      grant.client_id !== intent.client_id ||
      intent.binding_id !== bindingId ||
      intent.enrollment_tx_id !== enrollmentTxId ||
      intent.reservation_id !== reservationId ||
      intent.oauth_grant_id !== oauthGrantId ||
      intent.registration_invite_id !== reservation.registration_invite_id ||
      enrollment.binding_id !== bindingId ||
      enrollment.bootstrap_intent_id !== bootstrapIntentId ||
      enrollment.reservation_id !== reservationId ||
      enrollment.oauth_grant_id !== oauthGrantId ||
      reservation.binding_id !== bindingId ||
      reservation.bootstrap_intent_id !== bootstrapIntentId ||
      reservation.enrollment_tx_id !== enrollmentTxId) {
    throw makeError("OAUTH_ACTIVATION_LINEAGE_INVALID", "Activation lineage mismatch", 409);
  }
  if (reservation.quota_epoch !== invite.quota_epoch || intent.quota_epoch !== invite.quota_epoch ||
      (quotaEpoch !== undefined && quotaEpoch !== invite.quota_epoch)) {
    throw makeError("RESERVATION_EPOCH_STALE", "Activation quota epoch is stale", 409);
  }
  return { binding, grant, intent, enrollment, reservation, invite };
}

function resolveOAuthActiveAttemptLineage(store, options = {}) {
  const activationAttemptId = options?.activationAttemptId;
  if (typeof activationAttemptId !== "string" ||
      !OAUTH_ACTIVATION_ATTEMPT_ID_PATTERN.test(activationAttemptId)) {
    throw makeError("OAUTH_ACTIVATION_STALE", "Activation attempt identity is invalid", 409);
  }
  if (!Number.isInteger(options?.quotaEpoch) || options.quotaEpoch < 1) {
    throw makeError("OAUTH_ACTIVATION_STALE", "Activation quota epoch is invalid", 409);
  }

  const lineage = resolveOAuthActivationLineage(store, options);
  if (lineage.reservation.activation_attempt_id !== activationAttemptId ||
      lineage.enrollment.activation_attempt_id !== activationAttemptId) {
    throw makeError("OAUTH_ACTIVATION_STALE", "Activation attempt identity mismatch", 409);
  }
  return lineage;
}

function requireCapabilityObject(capabilities) {
  const merged = { ...DEFAULT_CAPABILITIES, ...(capabilities || {}) };
  for (const key of Object.keys(DEFAULT_CAPABILITIES)) {
    if (!CAPABILITY_STATES.includes(merged[key])) {
      throw makeError("INVALID_CAPABILITY_STATE", `Invalid capability ${key}`, 400);
    }
  }
  return merged;
}

function emptyStore() {
  return {
    schemaVersion: R7_SCHEMA_VERSION,
    storeRevision: 0,
    registrationInvites: [],
    registeredInstallations: [],
    installationBindings: [],
    enrollmentTransactions: [],
    registrationReservations: [],
    dcrClients: [],
    staticOAuthClients: [],
    dcrIdempotencyRecords: [],
    authorizationTransactions: [],
    oauthGrants: [],
    refreshTransactions: [],
    migrationAuthorizations: [],
    migrationAuthTransactions: [],
    bootstrapIntents: [],
    auditEvents: [],
  };
}

function findActiveOAuthClient(store, clientId) {
  const staticClient = store.staticOAuthClients?.find(
    (c) => c.client_id === clientId && c.status === "active"
  );
  if (staticClient) return staticClient;
  const dcrClient = store.dcrClients.find(
    (c) => c.client_id === clientId && c.status === "active"
  );
  return dcrClient || null;
}

function assertInteger(value, min, name) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new Error(`Invalid ${name}`);
  }
}

function assertStoreShape(store) {
  if (!store || store.schemaVersion !== R7_SCHEMA_VERSION) {
    throw new Error("R7 store schema mismatch");
  }
  assertInteger(store.storeRevision, 0, "storeRevision");
  for (const name of [
    "registrationInvites",
    "registeredInstallations",
    "installationBindings",
    "enrollmentTransactions",
    "registrationReservations",
    "bootstrapIntents",
    "auditEvents",
  ]) {
    if (!Array.isArray(store[name])) throw new Error(`Invalid R7 collection ${name}`);
  }

  const oauthCollections = [
    "dcrClients",
    "staticOAuthClients",
    "dcrIdempotencyRecords",
    "authorizationTransactions",
    "oauthGrants",
    "refreshTransactions",
    "migrationAuthorizations",
    "migrationAuthTransactions",
  ];
  for (const name of oauthCollections) {
    if (!Array.isArray(store[name])) {
      store[name] = [];
    }
  }

  const oauthClientIds = new Set();
  for (const client of store.dcrClients) {
    if (!client || typeof client.client_id !== "string" || client.client_id.length < 3 || client.client_id.length > 200) {
      throw new Error("Invalid DCR OAuth client id");
    }
    if (oauthClientIds.has(client.client_id)) throw new Error("Duplicate OAuth client_id");
    oauthClientIds.add(client.client_id);
  }

  for (const client of store.staticOAuthClients) {
    if (!client || client.client_type !== "STATIC_CONFIDENTIAL_GEMINI") throw new Error("Invalid static OAuth client type");
    if (typeof client.client_id !== "string" || client.client_id.length < 3 || client.client_id.length > 200) throw new Error("Invalid static OAuth client id");
    if (oauthClientIds.has(client.client_id)) throw new Error("Duplicate OAuth client_id");
    oauthClientIds.add(client.client_id);
    if (typeof client.client_name !== "string" || client.client_name.length === 0) throw new Error("Invalid static OAuth client name");
    if (!Array.isArray(client.redirect_uris) || client.redirect_uris.length === 0) throw new Error("Invalid static OAuth redirect_uris");
    if (client.token_endpoint_auth_method !== "client_secret_post") throw new Error("Invalid static OAuth auth method");
    if (typeof client.client_secret_hash !== "string" || !/^[A-F0-9]{64}$/.test(client.client_secret_hash)) throw new Error("Invalid static OAuth client secret hash");
    if (Object.prototype.hasOwnProperty.call(client, "client_secret")) throw new Error("Raw static OAuth client secret persisted");
    if (client.status !== "active") throw new Error("Invalid static OAuth client status");
  }
  const inviteIds = new Set();
  for (const row of store.registrationInvites) {
    if (inviteIds.has(row.registration_invite_id)) throw new Error("Duplicate registration_invite_id");
    inviteIds.add(row.registration_invite_id);
    if (typeof row.credential_hash !== "string" || !/^[A-F0-9]{64}$/.test(row.credential_hash)) {
      throw new Error("Invalid invite credential hash");
    }
    if (Object.prototype.hasOwnProperty.call(row, "credential")) {
      throw new Error("Raw invite credential persisted");
    }
    assertInteger(row.registrations_lifetime, 0, "registrations_lifetime");
    assertInteger(row.quota_epoch, 1, "quota_epoch");
    if (row.quota_epoch_max !== null) assertInteger(row.quota_epoch_max, 1, "quota_epoch_max");
    assertInteger(row.quota_epoch_used, 0, "quota_epoch_used");
    assertInteger(row.registrations_active, 0, "registrations_active");
    assertInteger(row.registrations_reserved, 0, "registrations_reserved");
    assertInteger(row.record_revision, 1, "invite record_revision");
    if (row.quota_epoch_max !== null &&
        row.quota_epoch_used + row.registrations_reserved > row.quota_epoch_max) {
      throw new Error("Quota invariant violated");
    }
  }

  const registrationIds = new Set();
  for (const row of store.registeredInstallations) {
    if (registrationIds.has(row.registration_id)) throw new Error("Duplicate registration_id");
    registrationIds.add(row.registration_id);
    if (!inviteIds.has(row.registration_invite_id)) throw new Error("Registration invite FK missing");
    if (!["active", "disabled", "revoked", "retired"].includes(row.status)) {
      throw new Error("Invalid registration status");
    }
  }

  const bindingIds = new Set();
  const bindingRegistrationIds = new Set();
  const enrollmentBindingIds = new Set();
  const proofKeys = new Set();
  for (const row of store.installationBindings) {
    if (bindingIds.has(row.binding_id)) throw new Error("Duplicate binding_id");
    bindingIds.add(row.binding_id);
    if (!BINDING_STATES.includes(row.binding_state)) throw new Error("Invalid binding_state");
    if (row.registration_id !== null) {
      if (bindingRegistrationIds.has(row.registration_id)) throw new Error("Duplicate binding registration");
      bindingRegistrationIds.add(row.registration_id);
      if (!registrationIds.has(row.registration_id)) throw new Error("Binding registration FK missing");
    } else if (!["provisional", "revoked", "expired_cleanup"].includes(row.binding_state)) {
      throw new Error("Only provisional, revoked, or expired_cleanup binding may omit registration_id");
    }
    if (row.enrollment_tx_id !== null) {
      if (enrollmentBindingIds.has(row.enrollment_tx_id)) throw new Error("Duplicate binding enrollment_tx_id");
      enrollmentBindingIds.add(row.enrollment_tx_id);
    }
    if (row.proof_identity_key !== null) {
      const k = `${row.adapter_type}:${row.proof_identity_key}`;
      if (proofKeys.has(k)) throw new Error("Duplicate proof_identity_key");
      proofKeys.add(k);
    }
    if (row.credential_generation === 0) {
      if (!row.legacy_migration || !["migration_unbound", "revoked", "disabled"].includes(row.binding_state)) {
        throw new Error("Generation 0 restricted to migrated lineage");
      }
    } else {
      assertInteger(row.credential_generation, 1, "credential_generation");
      if (!ADAPTER_TYPES.includes(row.adapter_type)) throw new Error("Invalid adapter_type");
      if (row.binding_state === "provisional" || row.binding_state === "expired_cleanup") {
        // Provisional or expired cleanup binding may omit proof_identity_key
      } else if (row.adapter_type.includes("OAUTH")) {
        if (!row.proof_identity_key) {
          throw new Error("Authoritative OAuth binding missing proof_identity_key");
        }
      } else {
        if (!row.proof_verifier_ref || !row.proof_fingerprint || !row.proof_identity_key) {
          throw new Error("Authoritative binding missing proof state");
        }
      }
    }
    if (Object.prototype.hasOwnProperty.call(row, "raw_secret") ||
        Object.prototype.hasOwnProperty.call(row, "access_token") ||
        Object.prototype.hasOwnProperty.call(row, "refresh_token")) {
      throw new Error("Raw proof secret persisted");
    }
    requireCapabilityObject(row.capability_status);
  }

  const txIds = new Set();
  for (const row of store.enrollmentTransactions) {
    if (txIds.has(row.enrollment_tx_id)) throw new Error("Duplicate enrollment_tx_id");
    txIds.add(row.enrollment_tx_id);
    if (row.binding_id !== null && row.binding_id !== undefined && !bindingIds.has(row.binding_id)) {
      throw new Error("Enrollment binding FK missing");
    }
  }

  const reservationIds = new Set();
  for (const row of store.registrationReservations) {
    if (reservationIds.has(row.reservation_id)) throw new Error("Duplicate reservation_id");
    reservationIds.add(row.reservation_id);
    if (row.binding_id !== null && row.binding_id !== undefined && !bindingIds.has(row.binding_id)) {
      throw new Error("Reservation binding FK missing");
    }
    if (row.bootstrap_intent_id && Object.prototype.hasOwnProperty.call(row, "status")) {
      const state = reservationLifecycleState(row);
      if (!["reserved", "initializing", "committing", "uncertain", "committed", "released", "expired"].includes(state)) {
        throw new Error("Invalid bootstrap reservation status");
      }
      if (row.activation_attempt_id !== undefined && row.activation_attempt_id !== null &&
          !/^whr7act_[0-9a-f-]{36}$/i.test(String(row.activation_attempt_id))) {
        throw new Error("Invalid activation attempt id");
      }
      if (OAUTH_ACTIVATION_BLOCKING_STATES.has(state)) {
        if (!row.activation_attempt_id || typeof row.activation_started_at !== "string") {
          throw new Error("Blocking activation state missing durable activation metadata");
        }
      }
    }
  }

  const bootstrapIds = new Set();
  const terminalBootstrapStates = new Set(["committed", "denied", "expired", "released", "superseded"]);
  const liveBootstrapStates = new Set([
    "created",
    "awaiting_bootstrap",
    "bootstrap_verified",
    "quota_reserved",
    "code_issued",
    "code_redeemed",
    "installation_pending",
  ]);
  const liveReservationByIntent = new Set();
  for (const row of store.bootstrapIntents) {
    if (!row || typeof row.bootstrap_intent_id !== "string" || !row.bootstrap_intent_id.startsWith("whr7bi_")) {
      throw new Error("Invalid bootstrap intent id");
    }
    if (bootstrapIds.has(row.bootstrap_intent_id)) throw new Error("Duplicate bootstrap_intent_id");
    bootstrapIds.add(row.bootstrap_intent_id);
    if (!liveBootstrapStates.has(row.status) && !terminalBootstrapStates.has(row.status)) {
      throw new Error("Invalid bootstrap intent state");
    }
    for (const forbidden of ["invite", "invite_credential", "raw_invite", "form_body"]) {
      if (Object.prototype.hasOwnProperty.call(row, forbidden)) throw new Error("Raw invite persisted in bootstrap intent");
    }
    if (!/^[A-F0-9]{64}$/.test(String(row.request_fingerprint || "")) ||
        !/^[A-F0-9]{64}$/.test(String(row.oauth_state_hash || "")) ||
        !/^[A-F0-9]{64}$/.test(String(row.browser_session_hash || "")) ||
        !/^[A-F0-9]{64}$/.test(String(row.csrf_token_hash || ""))) {
      throw new Error("Invalid bootstrap intent hash field");
    }
    assertInteger(row.invite_attempt_count, 0, "bootstrap invite_attempt_count");
    assertInteger(row.record_revision, 1, "bootstrap record_revision");
    if (row.code_challenge_method !== "S256" || row.response_type !== "code") {
      throw new Error("Invalid bootstrap OAuth method");
    }
  }
  for (const row of store.registrationReservations) {
    if (row.bootstrap_intent_id && ["reserved", "initializing", "committing", "uncertain"].includes(row.status)) {
      if (!bootstrapIds.has(row.bootstrap_intent_id)) throw new Error("Reservation bootstrap intent FK missing");
      if (liveReservationByIntent.has(row.bootstrap_intent_id)) throw new Error("Multiple live reservations for bootstrap intent");
      liveReservationByIntent.add(row.bootstrap_intent_id);
    }
  }
}

function migrateStore(parsed) {
  if (!parsed || typeof parsed !== "object") throw new Error("R7 store invalid");
  if (parsed.schemaVersion === R7_SCHEMA_VERSION) return parsed;
  if (parsed.schemaVersion !== 3) throw new Error("R7 store schema mismatch");

  const requiredV3 = [
    "registrationInvites",
    "registeredInstallations",
    "installationBindings",
    "enrollmentTransactions",
    "registrationReservations",
    "dcrClients",
    "staticOAuthClients",
    "dcrIdempotencyRecords",
    "authorizationTransactions",
    "oauthGrants",
    "refreshTransactions",
    "migrationAuthorizations",
    "migrationAuthTransactions",
    "auditEvents",
  ];
  for (const name of requiredV3) {
    if (!Array.isArray(parsed[name])) throw new Error(`R7 v3 migration missing collection ${name}`);
  }
  if (Object.prototype.hasOwnProperty.call(parsed, "bootstrapIntents")) {
    throw new Error("R7 v3 migration contains unexpected bootstrapIntents");
  }

  return {
    ...parsed,
    schemaVersion: R7_SCHEMA_VERSION,
    bootstrapIntents: [],
  };
}

async function readStore(storePath) {
  try {
    const parsed = JSON.parse(await fs.readFile(storePath, "utf8"));
    const migrated = migrateStore(parsed);
    assertStoreShape(migrated);
    return migrated;
  } catch (error) {
    if (error?.code === "ENOENT") return emptyStore();
    throw error;
  }
}

async function writeStoreAtomic(storePath, store) {
  store.schemaVersion = R7_SCHEMA_VERSION;
  store.storeRevision += 1;
  assertStoreShape(store);
  const dir = path.dirname(storePath);
  await fs.mkdir(dir, { recursive: true });
  const temp = path.join(dir, `.${path.basename(storePath)}.${process.pid}.${randomUUID()}.tmp`);
  await fs.writeFile(temp, JSON.stringify(store, null, 2) + "\n", {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  try {
    await fs.rename(temp, storePath);
  } catch (error) {
    await fs.rm(temp, { force: true }).catch(() => {});
    throw error;
  }
}

async function acquireLock(lockPath, {
  timeoutMs = 5000,
  staleMs = 30000,
  retryDelayMs = 10,
  openLock = fs.open,
  platform = process.platform,
  nowMs = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  const started = nowMs();
  for (;;) {
    let handle;
    try {
      handle = await openLock(lockPath, "wx", 0o600);
    } catch (error) {
      if (error?.code === "EEXIST") {
        try {
          const stat = await fs.stat(lockPath);
          if (nowMs() - stat.mtimeMs > staleMs) {
            await fs.rm(lockPath, { force: true });
            continue;
          }
        } catch {}
        if (nowMs() - started > timeoutMs) {
          throw makeError("STORE_LOCK_TIMEOUT", "R7 store lock timeout", 503);
        }
        await sleep(retryDelayMs);
        continue;
      }

      const retryableWindowsLockOpen =
        platform === "win32" && (error?.code === "EPERM" || error?.code === "EACCES");
      if (!retryableWindowsLockOpen) throw error;
      if (nowMs() - started > timeoutMs) throw error;
      await sleep(retryDelayMs);
      continue;
    }

    try {
      await handle.writeFile(JSON.stringify({ pid: process.pid, createdAt: nowIso() }));
    } catch (error) {
      await handle.close().catch(() => {});
      await fs.rm(lockPath, { force: true }).catch(() => {});
      throw error;
    }

    return async () => {
      await handle.close().catch(() => {});
      await fs.rm(lockPath, { force: true }).catch(() => {});
    };
  }
}

export function defaultR7StorePath() {
  return path.join(os.homedir(), ".winhelm", "registered-oauth.json");
}

export function generateInviteCredential() {
  return INVITE_PREFIX + randomBytes(32).toString("base64url");
}

export function generateStaticProof() {
  return STATIC_PROOF_PREFIX + randomBytes(32).toString("base64url");
}

export class RegistrationStore {
  constructor({ storePath = defaultR7StorePath(), now = () => Date.now(), lockTestOptions = undefined } = {}) {
    this.storePath = storePath;
    this.lockPath = storePath + ".lock";
    this.now = now;
    this._lockOptions = lockTestOptions;
  }

  async _read() {
    return readStore(this.storePath);
  }

  async _mutate(fn) {
    const release = await acquireLock(this.lockPath, this._lockOptions);
    try {
      const store = await readStore(this.storePath);
      const result = await fn(store);
      await writeStoreAtomic(this.storePath, store);
      return clone(result);
    } finally {
      await release();
    }
  }

  _audit(store, event, data = {}) {
    store.auditEvents.push({
      audit_id: randomUUID(),
      event,
      at: nowIso(this.now()),
      ...data,
    });
    if (store.auditEvents.length > 10000) store.auditEvents.splice(0, store.auditEvents.length - 10000);
  }

  async snapshot() {
    return clone(await this._read());
  }

  async createInvite({
    aliasName,
    quotaMax = 1,
    expiresAt = null,
    allowedPaths = ["/mcp"],
    allowedTransports = ["authorization"],
  } = {}) {
    if (typeof aliasName !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(aliasName)) {
      throw makeError("INVALID_ALIAS_NAME", "Invalid alias name", 400);
    }
    if (quotaMax !== null) assertInteger(quotaMax, 1, "quotaMax");
    const credential = generateInviteCredential();
    const credentialHash = sha256(credential);
    const createdAt = nowIso(this.now());
    const id = randomUUID();
    const row = await this._mutate((store) => {
      if (store.registrationInvites.some((x) => x.alias_name === aliasName && x.status !== "retired")) {
        throw makeError("INVITE_ALIAS_CONFLICT", "Invite alias already exists", 409);
      }
      const invite = {
        registration_invite_id: id,
        alias_name: aliasName,
        credential_hash: credentialHash,
        credential_fingerprint: fingerprint(credential),
        registrations_lifetime: 0,
        quota_epoch: 1,
        quota_epoch_max: quotaMax,
        quota_epoch_used: 0,
        quota_epoch_started_at: createdAt,
        quota_epoch_reason: "initial",
        quota_epoch_owner_action_id: null,
        registrations_active: 0,
        registrations_reserved: 0,
        created_at: createdAt,
        expires_at: expiresAt,
        status: "active",
        disabled_at: null,
        revoked_at: null,
        retired_at: null,
        record_revision: 1,
        allowed_paths: [...allowedPaths],
        allowed_transports: [...allowedTransports],
        max_concurrent_sessions_per_installation: 1,
      };
      store.registrationInvites.push(invite);
      this._audit(store, "REGISTRATION_INVITE_CREATED", {
        registration_invite_id: id,
        credential_fingerprint: invite.credential_fingerprint,
      });
      return invite;
    });
    return { invite: row, credential };
  }

  async authenticateInvite(credential) {
    if (typeof credential !== "string" || credential.length < 20) {
      throw makeError("INVITE_INVALID", "Registration invite invalid", 401);
    }
    const hash = sha256(credential);
    const store = await this._read();
    const invite = store.registrationInvites.find((x) => safeEqualHex(x.credential_hash, hash));
    if (!invite) throw makeError("INVITE_INVALID", "Registration invite invalid", 401);
    this._assertInviteEnrollAuthority(invite);
    return clone(invite);
  }

  _assertInviteEnrollAuthority(invite) {
    const now = this.now();
    if (invite.status !== "active") {
      if (invite.status === "exhausted") throw makeError("REGISTRATION_QUOTA_EXHAUSTED", "Registration quota exhausted", 409);
      throw makeError("INVITE_NOT_ACTIVE", "Registration invite not active", 403);
    }
    if (invite.expires_at && Date.parse(invite.expires_at) <= now) {
      throw makeError("INVITE_EXPIRED", "Registration invite expired", 403);
    }
    if (invite.quota_epoch_max !== null &&
        invite.quota_epoch_used + invite.registrations_reserved >= invite.quota_epoch_max) {
      if (invite.quota_epoch_used >= invite.quota_epoch_max) {
        throw makeError("REGISTRATION_QUOTA_EXHAUSTED", "Registration quota exhausted", 409);
      }
      throw makeError("REGISTRATION_QUOTA_RESERVED", "Registration quota temporarily reserved", 409);
    }
  }

  async establishStaticBinding({
    inviteCredential,
    adapterType,
    proofSecret,
    capabilities,
  }) {
    if (!["CLAUDE_UNIQUE_FIXED_HEADER", "CURSOR_UNIQUE_STATIC_HEADER"].includes(adapterType)) {
      throw makeError("INSTALLATION_BINDING_INVALID", "Static proof adapter not allowed", 401);
    }
    if (typeof proofSecret !== "string" || !proofSecret.startsWith(STATIC_PROOF_PREFIX) || proofSecret.length < 40) {
      throw makeError("INSTALLATION_BINDING_INVALID", "Invalid installation proof", 401);
    }
    const inviteHash = sha256(inviteCredential);
    const proofFp = fingerprint(proofSecret);
    const caps = requireCapabilityObject(capabilities);
    return this._mutate((store) => {
      const invite = store.registrationInvites.find((x) => safeEqualHex(x.credential_hash, inviteHash));
      if (!invite) throw makeError("INVITE_INVALID", "Registration invite invalid", 401);

      const existing = store.installationBindings.filter((b) => b.adapter_type === adapterType && b.proof_fingerprint === proofFp);
      for (const row of existing) {
        if (verifyScrypt(proofSecret, row.proof_verifier_ref)) {
          if (row.registration_invite_id !== invite.registration_invite_id) {
            throw makeError("ENROLLMENT_REPLAY_CONFLICT", "Proof already belongs to another invite", 409);
          }
          const tx = row.enrollment_tx_id
            ? store.enrollmentTransactions.find((x) => x.enrollment_tx_id === row.enrollment_tx_id)
            : null;
          return { binding: row, enrollment: tx, recovered: true };
        }
      }

      this._assertInviteEnrollAuthority(invite);
      for (const [key, value] of Object.entries(caps)) {
        if (value !== "PASS" && ["fresh_reinstall_boundary", "binding_rotation_supported", "binding_revocation_supported", "lost_response_recovery_supported"].includes(key)) {
          throw makeError("INSTALLATION_BINDING_CAPABILITY_UNVERIFIED", `Mandatory capability ${key} is not PASS`, 503);
        }
      }

      const bindingId = randomUUID();
      const txId = randomUUID();
      const createdAt = nowIso(this.now());
      const binding = {
        binding_id: bindingId,
        registration_id: null,
        registration_invite_id: invite.registration_invite_id,
        adapter_type: adapterType,
        binding_state: "provisional",
        credential_generation: 1,
        enrollment_tx_id: txId,
        created_at: createdAt,
        last_authenticated_at: createdAt,
        rotated_at: null,
        revoked_at: null,
        disabled_at: null,
        capability_status: caps,
        record_revision: 1,
        proof_verifier_ref: scryptVerifier(proofSecret),
        proof_fingerprint: proofFp,
        proof_identity_key: randomUUID(),
        pending_credential_generation: null,
        pending_proof_verifier_ref: null,
        pending_proof_fingerprint: null,
        rotation_tx_id: null,
        migration_bound_at: null,
        legacy_migration: false,
      };
      const tx = {
        enrollment_tx_id: txId,
        binding_id: bindingId,
        registration_invite_id: invite.registration_invite_id,
        credential_generation: 1,
        quota_epoch: null,
        reservation_id: null,
        registration_id: null,
        state: "binding_established",
        created_at: createdAt,
        updated_at: createdAt,
        committed_at: null,
        record_revision: 1,
      };
      store.installationBindings.push(binding);
      store.enrollmentTransactions.push(tx);
      this._audit(store, "INSTALLATION_BINDING_PROVISIONED", {
        binding_id: bindingId,
        registration_invite_id: invite.registration_invite_id,
        adapter_type: adapterType,
        proof_fingerprint: proofFp,
        credential_generation: 1,
      });
      return { binding, enrollment: tx, recovered: false };
    });
  }

  async establishOAuthBinding({
    inviteCredential,
    adapterType,
    grantVerifierRef,
    grantIdentityKey,
    grantFingerprint,
    capabilities,
  }) {
    if (!["CHATGPT_OAUTH_DCR_GRANT", "GEMINI_STATIC_OAUTH_GRANT", "CLAUDE_OAUTH_DCR_GRANT"].includes(adapterType)) {
      throw makeError("INSTALLATION_BINDING_INVALID", "OAuth adapter not allowed", 401);
    }
    const caps = requireCapabilityObject(capabilities);
    const mandatory = ["fresh_reinstall_boundary", "refresh_persistence", "binding_rotation_supported", "binding_revocation_supported", "lost_response_recovery_supported"];
    if (mandatory.some((k) => caps[k] !== "PASS")) {
      throw makeError("INSTALLATION_BINDING_CAPABILITY_UNVERIFIED", "OAuth adapter capability not qualified", 503);
    }
    if (!grantVerifierRef || !grantIdentityKey || !grantFingerprint) {
      throw makeError("INSTALLATION_BINDING_REQUIRED", "Validated OAuth grant context required", 401);
    }
    const inviteHash = sha256(inviteCredential);
    return this._mutate((store) => {
      const invite = store.registrationInvites.find((x) => safeEqualHex(x.credential_hash, inviteHash));
      if (!invite) throw makeError("INVITE_INVALID", "Registration invite invalid", 401);

      const existing = store.installationBindings.find((b) =>
        b.adapter_type === adapterType && b.proof_identity_key === grantIdentityKey);
      if (existing) {
        if (existing.registration_invite_id !== invite.registration_invite_id) {
          throw makeError("ENROLLMENT_REPLAY_CONFLICT", "OAuth grant already belongs to another invite", 409);
        }
        const tx = existing.enrollment_tx_id
          ? store.enrollmentTransactions.find((x) => x.enrollment_tx_id === existing.enrollment_tx_id)
          : null;
        return { binding: existing, enrollment: tx, recovered: true };
      }

      this._assertInviteEnrollAuthority(invite);
      const bindingId = randomUUID();
      const txId = randomUUID();
      const createdAt = nowIso(this.now());
      const binding = {
        binding_id: bindingId,
        registration_id: null,
        registration_invite_id: invite.registration_invite_id,
        adapter_type: adapterType,
        binding_state: "provisional",
        credential_generation: 1,
        enrollment_tx_id: txId,
        created_at: createdAt,
        last_authenticated_at: createdAt,
        rotated_at: null,
        revoked_at: null,
        disabled_at: null,
        capability_status: caps,
        record_revision: 1,
        proof_verifier_ref: String(grantVerifierRef),
        proof_fingerprint: String(grantFingerprint),
        proof_identity_key: String(grantIdentityKey),
        pending_credential_generation: null,
        pending_proof_verifier_ref: null,
        pending_proof_fingerprint: null,
        rotation_tx_id: null,
        migration_bound_at: null,
        legacy_migration: false,
      };
      const tx = {
        enrollment_tx_id: txId,
        binding_id: bindingId,
        registration_invite_id: invite.registration_invite_id,
        credential_generation: 1,
        quota_epoch: null,
        reservation_id: null,
        registration_id: null,
        state: "binding_established",
        created_at: createdAt,
        updated_at: createdAt,
        committed_at: null,
        record_revision: 1,
      };
      store.installationBindings.push(binding);
      store.enrollmentTransactions.push(tx);
      this._audit(store, "INSTALLATION_BINDING_PROVISIONED", {
        binding_id: bindingId,
        adapter_type: adapterType,
        proof_fingerprint: String(grantFingerprint),
        credential_generation: 1,
      });
      return { binding, enrollment: tx, recovered: false };
    });
  }

  async reserveEnrollment(bindingId) {
    return this._mutate((store) => {
      const binding = store.installationBindings.find((x) => x.binding_id === bindingId);
      if (!binding) throw makeError("INSTALLATION_BINDING_INVALID", "Binding not found", 401);
      if (binding.binding_state !== "provisional") {
        if (binding.binding_state === "active" && binding.registration_id) {
          const tx = store.enrollmentTransactions.find((x) => x.enrollment_tx_id === binding.enrollment_tx_id);
          return { recovered: true, binding, enrollment: tx };
        }
        throw makeError("INSTALLATION_BINDING_INVALID", "Binding not provisional", 409);
      }
      const invite = store.registrationInvites.find((x) => x.registration_invite_id === binding.registration_invite_id);
      if (!invite) throw makeError("INVITE_INVALID", "Invite missing", 401);

      let tx = store.enrollmentTransactions.find((x) => x.enrollment_tx_id === binding.enrollment_tx_id);
      if (!tx) throw makeError("ENROLLMENT_REPLAY_CONFLICT", "Enrollment transaction missing", 409);

      if (tx.reservation_id) {
        const reservation = store.registrationReservations.find((x) => x.reservation_id === tx.reservation_id);
        if (reservation && reservation.state === "reserved" && reservation.quota_epoch === invite.quota_epoch) {
          return { recovered: true, binding, enrollment: tx, reservation };
        }
        const newTxId = randomUUID();
        const at = nowIso(this.now());
        tx = {
          enrollment_tx_id: newTxId,
          binding_id: binding.binding_id,
          registration_invite_id: invite.registration_invite_id,
          credential_generation: binding.credential_generation,
          quota_epoch: null,
          reservation_id: null,
          registration_id: null,
          state: "binding_established",
          created_at: at,
          updated_at: at,
          committed_at: null,
          record_revision: 1,
        };
        binding.enrollment_tx_id = newTxId;
        binding.record_revision += 1;
        store.enrollmentTransactions.push(tx);
      }

      this._assertInviteEnrollAuthority(invite);
      const reservationId = randomUUID();
      const at = nowIso(this.now());
      const reservation = {
        reservation_id: reservationId,
        registration_invite_id: invite.registration_invite_id,
        quota_epoch: invite.quota_epoch,
        binding_id: binding.binding_id,
        enrollment_tx_id: tx.enrollment_tx_id,
        credential_generation: binding.credential_generation,
        state: "reserved",
        created_at: at,
        updated_at: at,
        committed_registration_id: null,
        released_at: null,
        release_reason: null,
        record_revision: 1,
      };
      invite.registrations_reserved += 1;
      invite.record_revision += 1;
      tx.quota_epoch = invite.quota_epoch;
      tx.reservation_id = reservationId;
      tx.state = "reserved";
      tx.updated_at = at;
      tx.record_revision += 1;
      store.registrationReservations.push(reservation);
      return { recovered: false, binding, enrollment: tx, reservation };
    });
  }

  async releaseEnrollmentReservation(bindingIdOrOpts, reservationId = null, reason = "core_initialize_failed") {
    const bindingId = typeof bindingIdOrOpts === "object" && bindingIdOrOpts !== null ? bindingIdOrOpts.bindingId : bindingIdOrOpts;
    const targetReservationId = typeof bindingIdOrOpts === "object" && bindingIdOrOpts !== null ? bindingIdOrOpts.reservationId : reservationId;
    const releaseReason = (typeof bindingIdOrOpts === "object" && bindingIdOrOpts !== null ? bindingIdOrOpts.reason : reason) || "core_initialize_failed";

    return this._mutate((store) => {
      const binding = store.installationBindings.find((x) => x.binding_id === bindingId);
      if (!binding) return { released: false, reason: "binding_not_found" };
      if (binding.binding_state === "active" && binding.registration_id) {
        return { released: false, reason: "already_committed" };
      }

      const tx = binding.enrollment_tx_id
        ? store.enrollmentTransactions.find((x) => x.enrollment_tx_id === binding.enrollment_tx_id)
        : null;

      let reservation = null;
      if (targetReservationId) {
        reservation = store.registrationReservations.find((x) => x.reservation_id === targetReservationId);
      } else if (tx?.reservation_id) {
        reservation = store.registrationReservations.find((x) => x.reservation_id === tx.reservation_id);
      }

      if (!reservation) {
        if (tx && tx.state === "reserved") {
          tx.state = "released";
          tx.updated_at = nowIso(this.now());
          tx.record_revision += 1;
        }
        return { released: false, reason: "reservation_not_found" };
      }

      const reservationState = reservation.status ?? reservation.state;
      if (reservationState === "committed" || reservation.committed_registration_id) {
        return { released: false, reason: "already_committed" };
      }
      if (reservationState === "released") {
        return { released: false, reason: "already_released" };
      }
      if (reservation.bootstrap_intent_id &&
          (reservation.activation_attempt_id || OAUTH_ACTIVATION_BLOCKING_STATES.has(reservationState))) {
        throw makeError(
          "OAUTH_ACTIVATION_STALE",
          "OAuth activation release requires exact activation attempt handling",
          409,
        );
      }

      const isLive = ["reserved", "initializing", "committing"].includes(reservationState);
      if (!isLive) {
        return { released: false, reason: `already_${reservationState}` };
      }

      const at = nowIso(this.now());
      if (Object.prototype.hasOwnProperty.call(reservation, "status")) reservation.status = "released";
      if (Object.prototype.hasOwnProperty.call(reservation, "state")) reservation.state = "released";
      reservation.released_at = at;
      reservation.release_reason = releaseReason;
      reservation.updated_at = at;
      reservation.record_revision += 1;

      if (tx && tx.reservation_id === reservation.reservation_id) {
        if (Object.prototype.hasOwnProperty.call(tx, "status")) tx.status = "released";
        if (Object.prototype.hasOwnProperty.call(tx, "state")) tx.state = "released";
        tx.updated_at = at;
        tx.record_revision += 1;
      }

      const invite = store.registrationInvites.find((x) => x.registration_invite_id === reservation.registration_invite_id);
      if (invite) {
        if (reservation.quota_epoch === invite.quota_epoch && invite.registrations_reserved > 0) {
          invite.registrations_reserved -= 1;
          invite.record_revision += 1;
        }
      }

      if (reservation.bootstrap_intent_id) {
        const intent = store.bootstrapIntents.find((i) => i.bootstrap_intent_id === reservation.bootstrap_intent_id);
        if (intent && !["committed", "denied", "expired", "released", "superseded"].includes(intent.status)) {
          intent.status = "released";
          intent.released_at = at;
          intent.release_reason = releaseReason;
          intent.updated_at = at;
          intent.record_revision += 1;
        }
        for (const grant of store.oauthGrants) {
          if (grant.bootstrap_intent_id === reservation.bootstrap_intent_id && grant.status === "active") {
            grant.status = "expired_cleanup";
            grant.record_revision += 1;
          }
        }
        if (binding.binding_state === "provisional") {
          binding.binding_state = "expired_cleanup";
          binding.record_revision += 1;
        }
      }

      this._audit(store, "REGISTRATION_RESERVATION_RELEASED", {
        bootstrap_intent_id: reservation.bootstrap_intent_id ?? null,
        registration_invite_id: reservation.registration_invite_id,
        binding_id: binding.binding_id,
        enrollment_tx_id: tx?.enrollment_tx_id || reservation.enrollment_tx_id,
        reservation_id: reservation.reservation_id,
        quota_epoch: reservation.quota_epoch,
        reason: releaseReason,
      });

      return { released: true, binding, enrollment: tx, reservation };
    });
  }

  async commitEnrollment(bindingId, { clientRegistrationSnapshot = null } = {}) {
    return this._mutate((store) => {
      const binding = store.installationBindings.find((x) => x.binding_id === bindingId);
      if (!binding) throw makeError("INSTALLATION_BINDING_INVALID", "Binding not found", 401);
      if (binding.binding_state === "active" && binding.registration_id) {
        const registration = store.registeredInstallations.find((x) => x.registration_id === binding.registration_id);
        const tx = store.enrollmentTransactions.find((x) => x.enrollment_tx_id === binding.enrollment_tx_id);
        this._audit(store, "ENROLLMENT_RECOVERED_AFTER_LOST_RESPONSE", {
          binding_id: binding.binding_id,
          registration_id: binding.registration_id,
          enrollment_tx_id: binding.enrollment_tx_id,
        });
        return { recovered: true, binding, registration, enrollment: tx };
      }
      if (binding.binding_state !== "provisional") {
        throw makeError("INSTALLATION_BINDING_INVALID", "Binding cannot commit", 409);
      }
      for (const [key, state] of Object.entries(binding.capability_status)) {
        if (["fresh_reinstall_boundary", "binding_rotation_supported", "binding_revocation_supported", "lost_response_recovery_supported"].includes(key) && state !== "PASS") {
          throw makeError("INSTALLATION_BINDING_CAPABILITY_UNVERIFIED", `Mandatory capability ${key} is not PASS`, 503);
        }
      }
      const tx = store.enrollmentTransactions.find((x) => x.enrollment_tx_id === binding.enrollment_tx_id);
      if (!tx || !tx.reservation_id) throw makeError("ENROLLMENT_REPLAY_CONFLICT", "Reservation required", 409);
      const reservation = store.registrationReservations.find((x) => x.reservation_id === tx.reservation_id);
      if (!reservation || reservation.state !== "reserved") {
        throw makeError("ENROLLMENT_REPLAY_CONFLICT", "Reservation is not live", 409);
      }
      const invite = store.registrationInvites.find((x) => x.registration_invite_id === binding.registration_invite_id);
      if (!invite) throw makeError("INVITE_INVALID", "Invite missing", 401);
      this._assertInviteEnrollAuthorityForCommit(invite);
      if (reservation.quota_epoch !== invite.quota_epoch) {
        reservation.state = "invalidated_epoch_renewal";
        reservation.updated_at = nowIso(this.now());
        reservation.record_revision += 1;
        if (invite.registrations_reserved > 0) invite.registrations_reserved -= 1;
        invite.record_revision += 1;
        tx.state = "invalidated_epoch_renewal";
        tx.updated_at = nowIso(this.now());
        tx.record_revision += 1;
        throw makeError("ENROLLMENT_REPLAY_CONFLICT", "Reservation epoch is stale", 409);
      }
      if (reservation.credential_generation !== binding.credential_generation) {
        throw makeError("INSTALLATION_BINDING_INVALID", "Credential generation changed", 401);
      }

      const at = nowIso(this.now());
      const registrationId = randomUUID();
      const installSequence = invite.registrations_lifetime + 1;
      const registration = {
        registration_id: registrationId,
        registration_invite_id: invite.registration_invite_id,
        admitted_quota_epoch: invite.quota_epoch,
        install_sequence: installSequence,
        status: "active",
        first_registered_at: at,
        last_seen_at: at,
        disabled_at: null,
        revoked_at: null,
        retired_at: null,
        client_registration_snapshot: clientRegistrationSnapshot,
        session_lease: {
          generation: 0,
          bound_session_id: null,
          session_state: null,
          bound_at: null,
          pending_init_id: null,
          pending_at: null,
          replacing_session_id: null,
        },
        record_revision: 1,
        legacy_migration: { migrated_from_r6: false },
      };
      store.registeredInstallations.push(registration);
      binding.registration_id = registrationId;
      binding.binding_state = "active";
      binding.record_revision += 1;
      tx.registration_id = registrationId;
      tx.state = "committed";
      tx.committed_at = at;
      tx.updated_at = at;
      tx.record_revision += 1;
      reservation.state = "committed";
      reservation.committed_registration_id = registrationId;
      reservation.updated_at = at;
      reservation.record_revision += 1;
      invite.registrations_lifetime += 1;
      invite.quota_epoch_used += 1;
      invite.registrations_active += 1;
      invite.registrations_reserved -= 1;
      if (invite.quota_epoch_max !== null && invite.quota_epoch_used >= invite.quota_epoch_max) {
        invite.status = "exhausted";
      }
      invite.record_revision += 1;
      this._audit(store, "REGISTRATION_COMMITTED", {
        registration_invite_id: invite.registration_invite_id,
        registration_id: registrationId,
        binding_id: binding.binding_id,
        enrollment_tx_id: tx.enrollment_tx_id,
        admitted_quota_epoch: invite.quota_epoch,
        install_sequence: installSequence,
      });
      return { recovered: false, binding, registration, enrollment: tx };
    });
  }

  _assertInviteEnrollAuthorityForCommit(invite) {
    const now = this.now();
    if (!["active", "exhausted"].includes(invite.status)) {
      throw makeError("INVITE_NOT_ACTIVE", "Invite not active", 403);
    }
    if (invite.expires_at && Date.parse(invite.expires_at) <= now) {
      throw makeError("INVITE_EXPIRED", "Invite expired", 403);
    }
    if (invite.quota_epoch_max !== null && invite.quota_epoch_used >= invite.quota_epoch_max) {
      throw makeError("REGISTRATION_QUOTA_EXHAUSTED", "Registration quota exhausted", 409);
    }
  }

  async authenticateStaticProof({ adapterType, proofSecret }) {
    if (!["CLAUDE_UNIQUE_FIXED_HEADER", "CURSOR_UNIQUE_STATIC_HEADER"].includes(adapterType)) {
      throw makeError("INSTALLATION_BINDING_INVALID", "Static proof adapter not allowed", 401);
    }
    const fp = fingerprint(proofSecret);
    const store = await this._read();
    const candidates = store.installationBindings.filter((b) => b.adapter_type === adapterType && b.proof_fingerprint === fp);
    for (const binding of candidates) {
      if (!verifyScrypt(proofSecret, binding.proof_verifier_ref)) continue;
      return this._authorizeBinding(store, binding);
    }
    throw makeError("INSTALLATION_BINDING_INVALID", "Installation proof invalid", 401);
  }

  async authenticateOAuthGrant({ adapterType, grantIdentityKey, grantVerifierRef = null }) {
    if (!["CHATGPT_OAUTH_DCR_GRANT", "GEMINI_STATIC_OAUTH_GRANT", "CLAUDE_OAUTH_DCR_GRANT"].includes(adapterType)) {
      throw makeError("INSTALLATION_BINDING_INVALID", "OAuth adapter not allowed", 401);
    }
    const store = await this._read();
    const binding = store.installationBindings.find((b) =>
      b.adapter_type === adapterType && b.proof_identity_key === grantIdentityKey);
    if (!binding) throw makeError("INSTALLATION_BINDING_INVALID", "OAuth grant binding not found", 401);
    if (grantVerifierRef !== null && binding.proof_verifier_ref !== grantVerifierRef) {
      throw makeError("INSTALLATION_BINDING_INVALID", "OAuth grant verifier mismatch", 401);
    }
    return this._authorizeBinding(store, binding);
  }

  _authorizeBinding(store, binding) {
    if (binding.binding_state === "rotating") throw makeError("INSTALLATION_BINDING_ROTATION_CONFLICT", "Binding rotation in progress", 409);
    if (binding.binding_state === "revoked") throw makeError("INSTALLATION_BINDING_REVOKED", "Binding revoked", 403);
    if (binding.binding_state === "disabled") throw makeError("INSTALLATION_BINDING_DISABLED", "Binding disabled", 403);
    if (binding.binding_state === "migration_unbound" || binding.credential_generation === 0) {
      throw makeError("INSTALLATION_BINDING_MIGRATION_REQUIRED", "Migration binding is unbound", 409);
    }
    if (binding.binding_state !== "active" || !binding.registration_id) {
      throw makeError("INSTALLATION_BINDING_REQUIRED", "Committed installation binding required", 401);
    }
    const registration = store.registeredInstallations.find((r) => r.registration_id === binding.registration_id);
    if (!registration || registration.status !== "active") {
      throw makeError("INSTALLATION_BINDING_DISABLED", "Registered installation not active", 403);
    }
    return clone({ binding, registration });
  }

  async touchAuthenticated(bindingId) {
    return this._mutate((store) => {
      const binding = store.installationBindings.find((x) => x.binding_id === bindingId);
      if (!binding) throw makeError("INSTALLATION_BINDING_INVALID", "Binding not found", 401);
      binding.last_authenticated_at = nowIso(this.now());
      binding.record_revision += 1;
      const registration = binding.registration_id
        ? store.registeredInstallations.find((x) => x.registration_id === binding.registration_id)
        : null;
      if (registration) {
        registration.last_seen_at = binding.last_authenticated_at;
        registration.record_revision += 1;
      }
      this._audit(store, "INSTALLATION_BINDING_AUTHENTICATED", {
        binding_id: bindingId,
        registration_id: binding.registration_id,
        adapter_type: binding.adapter_type,
        proof_fingerprint: binding.proof_fingerprint,
        credential_generation: binding.credential_generation,
      });
      return { binding, registration };
    });
  }

  async rotateStaticProof(bindingId, {
    currentProof,
    newProof,
    rotationTxId = randomUUID(),
  }) {
    return this._mutate((store) => {
      const binding = store.installationBindings.find((x) => x.binding_id === bindingId);
      if (!binding) throw makeError("INSTALLATION_BINDING_INVALID", "Binding not found", 401);
      if (!["CLAUDE_UNIQUE_FIXED_HEADER", "CURSOR_UNIQUE_STATIC_HEADER"].includes(binding.adapter_type)) {
        throw makeError("INSTALLATION_BINDING_ROTATION_CONFLICT", "Static rotation not supported for adapter", 409);
      }
      if (binding.capability_status.binding_rotation_supported !== "PASS") {
        throw makeError("INSTALLATION_BINDING_CAPABILITY_UNVERIFIED", "Rotation capability not PASS", 503);
      }
      if (binding.binding_state === "active") {
        if (!verifyScrypt(currentProof, binding.proof_verifier_ref)) {
          throw makeError("INSTALLATION_BINDING_INVALID", "Current proof invalid", 401);
        }
        binding.binding_state = "rotating";
        binding.pending_credential_generation = binding.credential_generation + 1;
        binding.pending_proof_verifier_ref = scryptVerifier(newProof);
        binding.pending_proof_fingerprint = fingerprint(newProof);
        binding.rotation_tx_id = rotationTxId;
        binding.record_revision += 1;
      } else if (binding.binding_state === "rotating") {
        if (binding.rotation_tx_id !== rotationTxId) {
          throw makeError("INSTALLATION_BINDING_ROTATION_CONFLICT", "Different rotation already in progress", 409);
        }
      } else {
        throw makeError("INSTALLATION_BINDING_ROTATION_CONFLICT", "Binding not rotatable", 409);
      }

      if (!verifyScrypt(newProof, binding.pending_proof_verifier_ref)) {
        throw makeError("INSTALLATION_BINDING_INVALID", "Candidate proof invalid", 401);
      }
      binding.proof_verifier_ref = binding.pending_proof_verifier_ref;
      binding.proof_fingerprint = binding.pending_proof_fingerprint;
      binding.proof_identity_key = randomUUID();
      binding.credential_generation = binding.pending_credential_generation;
      binding.pending_credential_generation = null;
      binding.pending_proof_verifier_ref = null;
      binding.pending_proof_fingerprint = null;
      binding.rotation_tx_id = null;
      binding.binding_state = "active";
      binding.rotated_at = nowIso(this.now());
      binding.last_authenticated_at = binding.rotated_at;
      binding.record_revision += 1;
      this._audit(store, "INSTALLATION_BINDING_ROTATED", {
        binding_id: binding.binding_id,
        registration_id: binding.registration_id,
        credential_generation: binding.credential_generation,
        proof_fingerprint: binding.proof_fingerprint,
      });
      return binding;
    });
  }

  async revokeBinding(bindingId) {
    return this._terminalizeBinding(bindingId, "revoked");
  }

  async disableBinding(bindingId) {
    return this._terminalizeBinding(bindingId, "disabled");
  }

  async _terminalizeBinding(bindingId, target) {
    return this._mutate((store) => {
      const binding = store.installationBindings.find((x) => x.binding_id === bindingId);
      if (!binding) throw makeError("INSTALLATION_BINDING_INVALID", "Binding not found", 401);
      if (binding.binding_state === "revoked") return binding;
      if (target === "disabled" && binding.binding_state === "disabled") return binding;
      const at = nowIso(this.now());
      binding.binding_state = target;
      if (target === "revoked") binding.revoked_at = at;
      if (target === "disabled") binding.disabled_at = at;
      binding.pending_credential_generation = null;
      binding.pending_proof_verifier_ref = null;
      binding.pending_proof_fingerprint = null;
      binding.rotation_tx_id = null;
      binding.record_revision += 1;
      if (binding.registration_id) {
        const registration = store.registeredInstallations.find((x) => x.registration_id === binding.registration_id);
        if (registration && registration.status === "active") {
          registration.status = target;
          if (target === "revoked") registration.revoked_at = at;
          if (target === "disabled") registration.disabled_at = at;
          registration.session_lease = {
            ...registration.session_lease,
            generation: registration.session_lease.generation + 1,
            bound_session_id: null,
            session_state: null,
            bound_at: null,
            pending_init_id: null,
            pending_at: null,
            replacing_session_id: null,
          };
          registration.record_revision += 1;
          const invite = store.registrationInvites.find((x) => x.registration_invite_id === registration.registration_invite_id);
          if (invite && invite.registrations_active > 0) {
            invite.registrations_active -= 1;
            invite.record_revision += 1;
          }
        }
      }
      this._audit(store, target === "revoked" ? "INSTALLATION_BINDING_REVOKED" : "INSTALLATION_BINDING_DISABLED", {
        binding_id: binding.binding_id,
        registration_id: binding.registration_id,
        credential_generation: binding.credential_generation,
      });
      return binding;
    });
  }

  async revokeInvite(inviteId, ownerActionId, reason = null) {
    if (!ownerActionId) throw makeError("OWNER_ACTION_ID_REQUIRED", "ownerActionId required", 400);
    return this._mutate((store) => {
      const invite = store.registrationInvites.find((i) => i.registration_invite_id === inviteId);
      if (!invite) throw makeError("INVITE_INVALID", "Invite not found", 404);
      const prior = store.auditEvents.find((e) =>
        e.event === "REGISTRATION_INVITE_REVOKED" &&
        e.registration_invite_id === inviteId &&
        e.owner_action_id === ownerActionId
      );
      if (prior) return invite;

      const at = nowIso(this.now());
      invite.status = "revoked";
      invite.revoked_at = at;
      invite.record_revision += 1;

      for (const reservation of store.registrationReservations) {
        const reservationState = reservation.status ?? reservation.state;
        if (reservation.registration_invite_id !== inviteId ||
            !["reserved", "initializing", "committing"].includes(reservationState)) continue;

        if (Object.prototype.hasOwnProperty.call(reservation, "status")) reservation.status = "released";
        if (Object.prototype.hasOwnProperty.call(reservation, "state")) reservation.state = "released";
        reservation.released_at = at;
        reservation.release_reason = "invite_revoked";
        reservation.record_revision += 1;
        if (reservation.quota_epoch === invite.quota_epoch && invite.registrations_reserved > 0) {
          invite.registrations_reserved -= 1;
          invite.record_revision += 1;
        }

        if (reservation.bootstrap_intent_id) {
          const intent = store.bootstrapIntents.find((i) => i.bootstrap_intent_id === reservation.bootstrap_intent_id);
          if (intent && !["committed", "denied", "expired", "released", "superseded"].includes(intent.status)) {
            intent.status = "released";
            intent.released_at = at;
            intent.release_reason = "invite_revoked";
            intent.updated_at = at;
            intent.record_revision += 1;
          }
          for (const grant of store.oauthGrants) {
            if (grant.bootstrap_intent_id === reservation.bootstrap_intent_id && grant.status === "active") {
              grant.status = "revoked";
              grant.revocation_reason = "INVITE_REVOKED";
              grant.revoked_at = at;
              grant.record_revision += 1;
            }
          }
          const binding = store.installationBindings.find((b) => b.binding_id === reservation.binding_id);
          if (binding && binding.registration_id === null) {
            binding.binding_state = "revoked";
            binding.revoked_at = at;
            binding.record_revision += 1;
          }
        }
      }

      this._audit(store, "REGISTRATION_INVITE_REVOKED", {
        registration_invite_id: inviteId,
        owner_action_id: ownerActionId,
        reason,
      });
      return invite;
    });
  }

  async increaseQuota(inviteId, newMax, ownerActionId) {
    assertInteger(newMax, 1, "newMax");
    if (!ownerActionId) throw makeError("OWNER_ACTION_ID_REQUIRED", "ownerActionId required", 400);
    return this._mutate((store) => {
      const invite = store.registrationInvites.find((x) => x.registration_invite_id === inviteId);
      if (!invite) throw makeError("INVITE_INVALID", "Invite not found", 404);
      if (invite.quota_epoch_owner_action_id === ownerActionId && invite.quota_epoch_max === newMax) return invite;
      if (invite.quota_epoch_max === null || newMax <= invite.quota_epoch_max) {
        throw makeError("QUOTA_INCREASE_INVALID", "Same-epoch quota may only increase", 409);
      }
      invite.quota_epoch_max = newMax;
      invite.quota_epoch_owner_action_id = ownerActionId;
      if (invite.status === "exhausted" && invite.quota_epoch_used < newMax) invite.status = "active";
      invite.record_revision += 1;
      this._audit(store, "QUOTA_INCREASED", {
        registration_invite_id: inviteId,
        quota_epoch: invite.quota_epoch,
        quota_epoch_max: newMax,
        owner_action_id: ownerActionId,
      });
      return invite;
    });
  }

  async renewQuotaEpoch(inviteId, newMax, ownerActionId, reason = null) {
    assertInteger(newMax, 1, "newMax");
    if (!ownerActionId) throw makeError("OWNER_ACTION_ID_REQUIRED", "ownerActionId required", 400);
    return this._mutate((store) => {
      const invite = store.registrationInvites.find((x) => x.registration_invite_id === inviteId);
      if (!invite) throw makeError("INVITE_INVALID", "Invite not found", 404);
      const priorAudit = store.auditEvents.find((e) => e.event === "QUOTA_EPOCH_RENEWED" && e.owner_action_id === ownerActionId);
      if (priorAudit) return invite;
      const oldEpoch = invite.quota_epoch;
      for (const reservation of store.registrationReservations) {
        if (reservation.registration_invite_id === inviteId &&
            reservation.quota_epoch === oldEpoch &&
            (reservation.state === "reserved" || reservation.status === "reserved")) {
          if (Object.prototype.hasOwnProperty.call(reservation, "state")) {
            reservation.state = "invalidated_epoch_renewal";
          }
          if (Object.prototype.hasOwnProperty.call(reservation, "status")) {
            reservation.status = "invalidated_epoch_renewal";
          }
          reservation.updated_at = nowIso(this.now());
          reservation.record_revision += 1;
          const tx = store.enrollmentTransactions.find((x) => x.enrollment_tx_id === reservation.enrollment_tx_id);
          if (tx) {
            if (Object.prototype.hasOwnProperty.call(tx, "state") && !["committed", "released", "expired"].includes(tx.state)) {
              tx.state = "invalidated_epoch_renewal";
            }
            if (Object.prototype.hasOwnProperty.call(tx, "status") && tx.status === "in_progress") {
              tx.status = "invalidated_epoch_renewal";
            }
            tx.updated_at = nowIso(this.now());
            tx.record_revision += 1;
          }
          if (reservation.bootstrap_intent_id) {
            const intent = store.bootstrapIntents.find((i) => i.bootstrap_intent_id === reservation.bootstrap_intent_id);
            if (intent && !["committed", "denied", "expired", "released", "superseded"].includes(intent.status)) {
              intent.status = "released";
              intent.released_at = nowIso(this.now());
              intent.release_reason = "quota_epoch_renewal";
              intent.updated_at = intent.released_at;
              intent.record_revision += 1;
            }
          }
        }
      }
      invite.quota_epoch += 1;
      invite.quota_epoch_used = 0;
      invite.quota_epoch_max = newMax;
      invite.registrations_reserved = 0;
      invite.quota_epoch_started_at = nowIso(this.now());
      invite.quota_epoch_reason = reason;
      invite.quota_epoch_owner_action_id = ownerActionId;
      if (invite.status === "exhausted") invite.status = "active";
      invite.record_revision += 1;
      this._audit(store, "QUOTA_EPOCH_RENEWED", {
        registration_invite_id: inviteId,
        prior_quota_epoch: oldEpoch,
        quota_epoch: invite.quota_epoch,
        quota_epoch_max: newMax,
        owner_action_id: ownerActionId,
      });
      return invite;
    });
  }

  async createR6Migration({
    aliasId,
    aliasName,
    legacyFingerprint,
    status = "active",
  }) {
    if (!aliasId || !aliasName || !legacyFingerprint) throw makeError("MIGRATION_INPUT_INVALID", "Migration input invalid", 400);
    return this._mutate((store) => {
      const existing = store.registeredInstallations.find((x) => x.registration_id === aliasId);
      if (existing) {
        const binding = store.installationBindings.find((x) => x.registration_id === aliasId);
        return { invite: store.registrationInvites.find((x) => x.registration_invite_id === existing.registration_invite_id), registration: existing, binding, recovered: true };
      }
      const at = nowIso(this.now());
      const inviteId = randomUUID();
      const invite = {
        registration_invite_id: inviteId,
        alias_name: aliasName,
        credential_hash: sha256("MIGRATED-NO-ENROLLMENT-" + randomUUID()),
        credential_fingerprint: String(legacyFingerprint),
        registrations_lifetime: 1,
        quota_epoch: 1,
        quota_epoch_max: 1,
        quota_epoch_used: 1,
        quota_epoch_started_at: at,
        quota_epoch_reason: "r6_migration",
        quota_epoch_owner_action_id: null,
        registrations_active: status === "active" ? 1 : 0,
        registrations_reserved: 0,
        created_at: at,
        expires_at: null,
        status: "exhausted",
        disabled_at: status === "disabled" ? at : null,
        revoked_at: status === "revoked" ? at : null,
        retired_at: null,
        record_revision: 1,
        allowed_paths: ["/mcp"],
        allowed_transports: ["authorization"],
        max_concurrent_sessions_per_installation: 1,
      };
      const registration = {
        registration_id: aliasId,
        registration_invite_id: inviteId,
        admitted_quota_epoch: 1,
        install_sequence: 1,
        status,
        first_registered_at: at,
        last_seen_at: null,
        disabled_at: status === "disabled" ? at : null,
        revoked_at: status === "revoked" ? at : null,
        retired_at: null,
        client_registration_snapshot: null,
        session_lease: {
          generation: 0,
          bound_session_id: null,
          session_state: null,
          bound_at: null,
          pending_init_id: null,
          pending_at: null,
          replacing_session_id: null,
        },
        record_revision: 1,
        legacy_migration: {
          migrated_from_r6: true,
          legacy_alias_id: aliasId,
          legacy_credential_fingerprint: String(legacyFingerprint),
        },
      };
      const bindingState = status === "active" ? "migration_unbound" : status;
      const binding = {
        binding_id: randomUUID(),
        registration_id: aliasId,
        registration_invite_id: inviteId,
        adapter_type: null,
        binding_state: bindingState,
        credential_generation: 0,
        enrollment_tx_id: null,
        created_at: at,
        last_authenticated_at: null,
        rotated_at: null,
        revoked_at: status === "revoked" ? at : null,
        disabled_at: status === "disabled" ? at : null,
        capability_status: { ...DEFAULT_CAPABILITIES },
        record_revision: 1,
        proof_verifier_ref: null,
        proof_fingerprint: null,
        proof_identity_key: null,
        pending_credential_generation: null,
        pending_proof_verifier_ref: null,
        pending_proof_fingerprint: null,
        rotation_tx_id: null,
        migration_bound_at: null,
        legacy_migration: true,
      };
      store.registrationInvites.push(invite);
      store.registeredInstallations.push(registration);
      store.installationBindings.push(binding);
      this._audit(store, "R6_REGISTRATION_MIGRATED_UNBOUND", {
        registration_id: aliasId,
        binding_id: binding.binding_id,
        legacy_credential_fingerprint: String(legacyFingerprint),
      });
      return { invite, registration, binding, recovered: false };
    });
  }

  async bindR6MigrationStatic(bindingId, {
    adapterType,
    proofSecret,
    capabilities,
    ownerActionId,
  }) {
    if (!ownerActionId) throw makeError("INSTALLATION_BINDING_MIGRATION_UNSAFE", "Independent Owner migration authorization required", 403);
    if (!["CLAUDE_UNIQUE_FIXED_HEADER", "CURSOR_UNIQUE_STATIC_HEADER"].includes(adapterType)) {
      throw makeError("INSTALLATION_BINDING_MIGRATION_UNSAFE", "Migration adapter unsupported", 403);
    }
    const caps = requireCapabilityObject(capabilities);
    if (caps.migration_handoff_supported !== "PASS" ||
        caps.binding_revocation_supported !== "PASS") {
      throw makeError("INSTALLATION_BINDING_CAPABILITY_UNVERIFIED", "Migration capability not PASS", 503);
    }
    return this._mutate((store) => {
      const binding = store.installationBindings.find((x) => x.binding_id === bindingId);
      if (!binding || binding.binding_state !== "migration_unbound" || binding.credential_generation !== 0) {
        throw makeError("INSTALLATION_BINDING_MIGRATION_REQUIRED", "Migration binding not eligible", 409);
      }
      const at = nowIso(this.now());
      binding.adapter_type = adapterType;
      binding.proof_verifier_ref = scryptVerifier(proofSecret);
      binding.proof_fingerprint = fingerprint(proofSecret);
      binding.proof_identity_key = randomUUID();
      binding.credential_generation = 1;
      binding.capability_status = caps;
      binding.binding_state = "active";
      binding.last_authenticated_at = at;
      binding.migration_bound_at = at;
      binding.record_revision += 1;
      this._audit(store, "INSTALLATION_BINDING_MIGRATED", {
        binding_id: binding.binding_id,
        registration_id: binding.registration_id,
        adapter_type: adapterType,
        proof_fingerprint: binding.proof_fingerprint,
        owner_action_id: ownerActionId,
      });
      return binding;
    });
  }

  async ensureStaticOAuthClient({
    clientId,
    clientName = "Gemini Static OAuth",
    redirectUris,
    clientSecret,
    omitIss = true,
    htmlHandoff = true,
  } = {}) {
    if (typeof clientId !== "string" || !/^[A-Za-z0-9._:-]{3,200}$/.test(clientId)) {
      throw makeError("INVALID_CLIENT_METADATA", "Invalid static client_id", 400);
    }
    if (typeof clientName !== "string" || clientName.trim().length === 0 || clientName.length > 200) {
      throw makeError("INVALID_CLIENT_METADATA", "Invalid static client_name", 400);
    }
    const validRedirect = validateRedirectUris(redirectUris);
    if (!validRedirect.ok) throw makeError("INVALID_REDIRECT_URI", validRedirect.error, 400);
    if (typeof clientSecret !== "string" || clientSecret.length < 32 || clientSecret.length > 1024) {
      throw makeError("INVALID_CLIENT_METADATA", "Static client secret must be 32..1024 characters", 400);
    }
    const secretHash = sha256Hex(clientSecret);
    return this._mutate((store) => {
      const collidingDcr = store.dcrClients.find((c) => c.client_id === clientId);
      if (collidingDcr) throw makeError("INVALID_CLIENT_METADATA", "Static client_id collides with DCR client", 409);
      const existing = store.staticOAuthClients.find((c) => c.client_id === clientId);
      if (existing) {
        const same = existing.status === "active" &&
          existing.client_name === clientName.trim() &&
          existing.token_endpoint_auth_method === "client_secret_post" &&
          safeEqualHex(existing.client_secret_hash, secretHash) &&
          JSON.stringify(existing.redirect_uris) === JSON.stringify(redirectUris) &&
          Boolean(existing.omit_iss) === Boolean(omitIss) &&
          Boolean(existing.html_handoff) === Boolean(htmlHandoff);
        if (!same) throw makeError("STATIC_CLIENT_CONFIG_MISMATCH", "Static OAuth client configuration mismatch", 409);
        return existing;
      }
      const at = nowIso(this.now());
      const client = {
        client_type: "STATIC_CONFIDENTIAL_GEMINI",
        client_id: clientId,
        client_name: clientName.trim(),
        redirect_uris: [...redirectUris],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: "winhelm:mcp",
        token_endpoint_auth_method: "client_secret_post",
        client_secret_hash: secretHash,
        omit_iss: Boolean(omitIss),
        html_handoff: Boolean(htmlHandoff),
        created_at: at,
        last_used_at: null,
        status: "active",
      };
      store.staticOAuthClients.push(client);
      this._audit(store, "oauth_static_client_configured", {
        client_id: clientId,
        client_type: client.client_type,
      });
      return client;
    });
  }

  async findOAuthClient(clientId) {
    const store = await this._read();
    return findActiveOAuthClient(store, clientId);
  }

  async authenticateTokenClient({ clientId, clientSecret = null } = {}) {
    if (!clientId || typeof clientId !== "string") throw makeError("INVALID_CLIENT", "client_id is required", 401);
    const store = await this._read();
    const client = findActiveOAuthClient(store, clientId);
    if (!client) throw makeError("INVALID_CLIENT", "Unknown or inactive client_id", 401);
    if (client.client_type === "STATIC_CONFIDENTIAL_GEMINI") {
      if (typeof clientSecret !== "string" || clientSecret.length === 0) {
        throw makeError("INVALID_CLIENT", "client_secret is required", 401);
      }
      if (!safeEqualHex(client.client_secret_hash, sha256Hex(clientSecret))) {
        throw makeError("INVALID_CLIENT", "Invalid client credentials", 401);
      }
    } else if (clientSecret !== null && clientSecret !== undefined && clientSecret !== "") {
      throw makeError("INVALID_CLIENT", "Public DCR clients must not authenticate with a client secret", 401);
    }
    return client;
  }
  async registerDcrClient(params = {}) {
    const clientName = params.client_name ?? params.clientName;
    const redirectUris = params.redirect_uris ?? params.redirectUris;
    const grantTypes = params.grant_types ?? params.grantTypes ?? ["authorization_code", "refresh_token"];
    const responseTypes = params.response_types ?? params.responseTypes ?? ["code"];
    const tokenEndpointAuthMethod = params.token_endpoint_auth_method ?? params.tokenEndpointAuthMethod ?? "none";
    const softwareId = params.software_id ?? params.softwareId ?? null;
    const softwareVersion = params.software_version ?? params.softwareVersion ?? null;
    const scope = params.scope ?? "winhelm:mcp";
    const idempotencyKey = params.idempotency_key ?? params.idempotencyKey ?? null;

    if (typeof clientName !== "string" || clientName.trim().length === 0) {
      throw makeError("INVALID_CLIENT_METADATA", "client_name is required", 400);
    }
    const validRedirect = validateRedirectUris(redirectUris);
    if (!validRedirect.ok) {
      throw makeError("INVALID_REDIRECT_URI", validRedirect.error, 400);
    }
    if (tokenEndpointAuthMethod !== "none") {
      throw makeError("INVALID_CLIENT_METADATA", "Only 'none' auth method supported for public clients", 400);
    }

    return this._mutate((store) => {
      if (store.dcrClients.length >= 200) {
        throw makeError("DCR_CAPACITY_EXCEEDED", "DCR client store ceiling reached", 503);
      }

      const rawPayload = {
        client_name: clientName,
        redirect_uris: redirectUris,
        grant_types: grantTypes,
        response_types: responseTypes,
        token_endpoint_auth_method: tokenEndpointAuthMethod,
        scope,
        software_id: softwareId,
        software_version: softwareVersion,
      };

      const canonicalPayload = canonicalizeDcrPayload(rawPayload);
      const payloadHash = computePayloadHash(canonicalPayload);
      const at = nowIso(this.now());
      const nowMs = this.now();

      if (idempotencyKey) {
        const keyHash = sha256Hex(idempotencyKey);
        const existingRecord = store.dcrIdempotencyRecords.find(
          (r) => r.idempotency_key_hash === keyHash && new Date(r.expires_at).getTime() > nowMs
        );

        if (existingRecord) {
          if (existingRecord.request_payload_hash === payloadHash) {
            const client = store.dcrClients.find((c) => c.client_id === existingRecord.resulting_client_id);
            if (client) {
              this._audit(store, "oauth_dcr_idempotent_replay", {
                client_id: client.client_id,
                idempotency_key_hash: keyHash,
              });
              return { status: 200, idempotentReplay: true, client };
            }
          } else {
            this._audit(store, "oauth_dcr_payload_mismatch_rejected", {
              idempotency_key_hash: keyHash,
            });
            throw makeError(
              "INVALID_CLIENT_METADATA",
              "Idempotency-Key payload mismatch: request metadata differs from original registration.",
              422
            );
          }
        }
      }

      const clientId = "whr7c_" + randomBytes(16).toString("hex");
      const client = {
        client_id: clientId,
        client_id_issued_at: Math.floor(nowMs / 1000),
        client_name: clientName,
        redirect_uris: redirectUris,
        grant_types: grantTypes,
        response_types: responseTypes,
        token_endpoint_auth_method: tokenEndpointAuthMethod,
        software_id: softwareId,
        software_version: softwareVersion,
        created_at: at,
        last_used_at: null,
        status: "active",
      };

      store.dcrClients.push(client);

      if (idempotencyKey) {
        const keyHash = sha256Hex(idempotencyKey);
        store.dcrIdempotencyRecords.push({
          idempotency_key_hash: keyHash,
          request_payload_hash: payloadHash,
          resulting_client_id: clientId,
          created_at: at,
          expires_at: nowIso(nowMs + 15 * 60 * 1000),
          status: "active",
          record_revision: 1,
        });
      }

      this._audit(store, "oauth_dcr_client_registered", {
        client_id: clientId,
        client_name: clientName,
      });

      return { status: 201, idempotentReplay: false, client };
    });
  }

  async findDcrClient(clientId) {
    const store = await this._read();
    return store.dcrClients.find((c) => c.client_id === clientId && c.status === "active") || null;
  }

  async validateAuthorizationRedirect({ clientId, redirectUri }) {
    if (!clientId || typeof clientId !== "string") {
      throw makeError("INVALID_CLIENT", "Unknown or inactive client_id", 400);
    }
    if (!redirectUri || typeof redirectUri !== "string") {
      throw makeError("INVALID_REQUEST", "redirect_uri is required", 400);
    }
    const store = await this._read();
    const client = findActiveOAuthClient(store, clientId);
    if (!client) {
      throw makeError("INVALID_CLIENT", "Unknown or inactive client_id", 400);
    }
    if (!matchesRedirectUri(client.redirect_uris, redirectUri)) {
      throw makeError("INVALID_REQUEST", "redirect_uri not registered for this client", 400);
    }
    return { client };
  }

  async createBootstrapIntent({
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod = "S256",
    state,
    scope = "winhelm:mcp",
    resource,
    authorizationAuthority,
    browserSessionHash,
    csrfTokenHash,
    adapterType = "CLAUDE_OAUTH_DCR_GRANT",
    ttlMs = 5 * 60 * 1000,
  }) {
    const canonicalScope = canonicalizeBootstrapScope(scope);
    if (canonicalScope !== "winhelm:mcp") throw makeError("INVALID_SCOPE", "Unsupported OAuth scope", 400);
    if (codeChallengeMethod !== "S256" || typeof codeChallenge !== "string" || codeChallenge.length < 43) {
      throw makeError("INVALID_REQUEST", "Valid S256 code_challenge required", 400);
    }
    if (typeof state !== "string" || state.length === 0 || state.length > 4096) {
      throw makeError("INVALID_REQUEST", "Bounded OAuth state required", 400);
    }
    if (typeof resource !== "string" || typeof authorizationAuthority !== "string") {
      throw makeError("INVALID_TARGET", "Trusted resource and authority required", 400);
    }
    if (resource !== `${authorizationAuthority}/mcp`) {
      throw makeError("INVALID_TARGET", "OAuth resource does not match authorization authority", 400);
    }
    if (!/^[A-F0-9]{64}$/.test(String(browserSessionHash || "")) ||
        !/^[A-F0-9]{64}$/.test(String(csrfTokenHash || ""))) {
      throw makeError("INVALID_REQUEST", "Bootstrap browser binding invalid", 400);
    }
    if (!ADAPTER_TYPES.includes(adapterType) || !adapterType.includes("OAUTH")) {
      throw makeError("INVALID_REQUEST", "Bootstrap adapter invalid", 400);
    }

    return this._mutate((store) => {
      const client = findActiveOAuthClient(store, clientId);
      if (!client) throw makeError("INVALID_CLIENT", "Unknown or inactive client_id", 400);
      if (!matchesRedirectUri(client.redirect_uris, redirectUri)) {
        throw makeError("INVALID_REQUEST", "redirect_uri not registered for this client", 400);
      }

      const nowMs = this.now();
      const at = nowIso(nowMs);
      const intentId = "whr7bi_" + randomBytes(32).toString("base64url");
      const requestFingerprint = computeBootstrapRequestFingerprint({
        clientId,
        redirectUri,
        authorizationAuthority,
        resource,
        scope: canonicalScope,
        responseType: "code",
        codeChallenge,
        codeChallengeMethod: "S256",
        state,
      });
      const intent = {
        bootstrap_intent_id: intentId,
        request_fingerprint: requestFingerprint,
        client_id: clientId,
        redirect_uri: redirectUri,
        resource,
        scope: canonicalScope,
        response_type: "code",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        oauth_state: state,
        oauth_state_hash: sha256Hex(state),
        authorization_authority: authorizationAuthority,
        adapter_type: adapterType,
        created_at: at,
        updated_at: at,
        expires_at: nowIso(nowMs + ttlMs),
        status: "awaiting_bootstrap",
        bootstrap_method: null,
        registration_invite_id: null,
        invite_fingerprint: null,
        invite_verified_at: null,
        approval_ref: null,
        owner_action_id: null,
        quota_epoch: null,
        reservation_id: null,
        enrollment_tx_id: null,
        binding_id: null,
        authorization_transaction_id: null,
        oauth_grant_id: null,
        registration_id: null,
        browser_session_hash: browserSessionHash,
        csrf_token_hash: csrfTokenHash,
        invite_attempt_count: 0,
        bootstrap_verified_at: null,
        quota_reserved_at: null,
        code_issued_at: null,
        code_redeemed_at: null,
        installation_pending_at: null,
        committed_at: null,
        denied_at: null,
        expired_at: null,
        released_at: null,
        superseded_at: null,
        superseded_by_intent_id: null,
        release_reason: null,
        record_revision: 1,
      };
      store.bootstrapIntents.push(intent);
      this._audit(store, "bootstrap_intent_created", {
        bootstrap_intent_id: intentId,
        client_id: clientId,
        resource,
      });
      return intent;
    });
  }

  async rotateBootstrapCsrf({ intentId, browserSessionHash }) {
    const result = await this._mutate((store) => {
      const intent = store.bootstrapIntents.find((i) => i.bootstrap_intent_id === intentId);
      if (!intent) return { ok: false, code: "BOOTSTRAP_INTENT_NOT_FOUND", status: 404 };
      const nowMs = this.now();
      if (new Date(intent.expires_at).getTime() <= nowMs) {
        if (!["committed", "denied", "expired", "released", "superseded"].includes(intent.status)) {
          intent.status = "expired";
          intent.expired_at = nowIso(nowMs);
          intent.updated_at = intent.expired_at;
          intent.record_revision += 1;
          this._audit(store, "bootstrap_expired", { bootstrap_intent_id: intentId });
        }
        return { ok: false, code: "BOOTSTRAP_INTENT_EXPIRED", status: 410 };
      }
      if (!safeEqualHex(intent.browser_session_hash, browserSessionHash)) {
        return { ok: false, code: "BOOTSTRAP_SESSION_MISMATCH", status: 403 };
      }
      if (!["awaiting_bootstrap", "bootstrap_verified"].includes(intent.status)) {
        return { ok: false, code: "BOOTSTRAP_INTENT_NOT_LIVE", status: 409 };
      }
      const csrfToken = randomBytes(32).toString("base64url");
      intent.csrf_token_hash = sha256Hex(csrfToken);
      intent.updated_at = nowIso(nowMs);
      intent.record_revision += 1;
      const client = findActiveOAuthClient(store, intent.client_id);
      return { ok: true, intent, csrfToken, clientName: client?.client_name || "OAuth client" };
    });
    if (!result.ok) throw makeError(result.code, result.code, result.status);
    return result;
  }

  async verifyBootstrapInviteAndIssueCode({
    intentId,
    browserSessionHash,
    csrfToken,
    browserContext = null,
    origin = null,
    inviteCredential,
    legacyTransport = false,
  }) {
    if (typeof inviteCredential !== "string" || inviteCredential.length < 20 || inviteCredential.length > 1024) {
      inviteCredential = "";
    }
    const inviteHash = sha256Hex(inviteCredential);
    const csrfHash = (typeof csrfToken === "string" && csrfToken.length > 0) ? sha256Hex(csrfToken) : null;

    const result = await this._mutate((store) => {
      const intent = store.bootstrapIntents.find((i) => i.bootstrap_intent_id === intentId);
      const nowMs = this.now();
      const at = nowIso(nowMs);
      if (!intent) return { ok: false, code: "BOOTSTRAP_INTENT_NOT_FOUND", status: 404, category: "security" };
      if (new Date(intent.expires_at).getTime() <= nowMs) {
        if (!["committed", "denied", "expired", "released", "superseded"].includes(intent.status)) {
          intent.status = "expired";
          intent.expired_at = at;
          intent.updated_at = at;
          intent.record_revision += 1;
          this._audit(store, "bootstrap_expired", { bootstrap_intent_id: intentId });
        }
        return { ok: false, code: "BOOTSTRAP_INTENT_EXPIRED", status: 410, category: "expired" };
      }
      if (intent.status !== "awaiting_bootstrap") {
        this._audit(store, "bootstrap_replay_rejected", { bootstrap_intent_id: intentId });
        return { ok: false, code: "BOOTSTRAP_REPLAY", status: 409, category: "security" };
      }
      const authCheck = evaluateBrowserAuthorityContext({
        browserContext,
        origin,
        intent,
        browserSessionHash,
        csrfHash,
        legacyTransport,
      });
      if (!authCheck.ok) {
        return { ok: false, code: authCheck.code, status: authCheck.status, category: "security" };
      }

      const client = findActiveOAuthClient(store, intent.client_id);
      if (!client || !matchesRedirectUri(client.redirect_uris, intent.redirect_uri)) {
        return { ok: false, code: "BOOTSTRAP_LINEAGE_INVALID", status: 409, category: "security" };
      }
      if (intent.resource !== `${intent.authorization_authority}/mcp` ||
          intent.scope !== "winhelm:mcp" ||
          intent.code_challenge_method !== "S256") {
        return { ok: false, code: "BOOTSTRAP_LINEAGE_INVALID", status: 409, category: "security" };
      }

      if (intent.invite_attempt_count >= 5) {
        intent.status = "denied";
        intent.denied_at = at;
        intent.updated_at = at;
        intent.record_revision += 1;
        return { ok: false, code: "BOOTSTRAP_ATTEMPT_LIMIT", status: 429, category: "unavailable" };
      }
      intent.invite_attempt_count += 1;
      intent.updated_at = at;
      intent.record_revision += 1;

      const invite = store.registrationInvites.find((i) => safeEqualHex(i.credential_hash, inviteHash));
      let unavailableReason = null;
      if (!invite) unavailableReason = "invite_not_found";
      else if (invite.status !== "active") unavailableReason = "invite_not_active";
      else if (invite.expires_at && new Date(invite.expires_at).getTime() <= nowMs) unavailableReason = "invite_expired";

      if (!unavailableReason) {
        const recoveryCandidates = store.bootstrapIntents
          .filter((prior) =>
            prior.bootstrap_intent_id !== intent.bootstrap_intent_id &&
            prior.registration_invite_id === invite.registration_invite_id &&
            prior.client_id === intent.client_id &&
            prior.redirect_uri === intent.redirect_uri &&
            prior.resource === intent.resource &&
            prior.authorization_authority === intent.authorization_authority &&
            prior.scope === intent.scope &&
            !prior.registration_id &&
            ["code_issued", "installation_pending"].includes(prior.status))
          .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());

        const prior = recoveryCandidates[0] || null;
        if (prior) {
          const supersession = evaluateBootstrapSupersession(store, prior, invite);

          if (!supersession.safe) {
            this._audit(store, "bootstrap_supersession_rejected", {
              bootstrap_intent_id: intent.bootstrap_intent_id,
              prior_bootstrap_intent_id: prior.bootstrap_intent_id,
              reason_code: "activation_in_progress",
            });
            return {
              ok: false,
              code: "BOOTSTRAP_ACTIVATION_IN_PROGRESS",
              status: 409,
              category: "activation_in_progress",
            };
          }

          intent.registration_invite_id = invite.registration_invite_id;
          intent.invite_fingerprint = invite.credential_fingerprint;
          intent.invite_verified_at = at;
          intent.bootstrap_verified_at = at;
          intent.recovery_candidate_intent_id = prior.bootstrap_intent_id;
          intent.status = "bootstrap_verified";
          intent.updated_at = at;
          intent.record_revision += 1;
          this._audit(store, "bootstrap_supersession_confirmation_required", {
            bootstrap_intent_id: intent.bootstrap_intent_id,
            prior_bootstrap_intent_id: prior.bootstrap_intent_id,
            registration_invite_id: invite.registration_invite_id,
          });
          return {
            ok: false,
            code: "BOOTSTRAP_SUPERSESSION_CONFIRMATION_REQUIRED",
            status: 409,
            category: "supersession_confirmation",
          };
        }
      }

      if (!unavailableReason && invite.quota_epoch_max !== null &&
          invite.quota_epoch_used + invite.registrations_reserved >= invite.quota_epoch_max) {
        unavailableReason = "quota_unavailable";
      }

      if (unavailableReason) {
        this._audit(store, "bootstrap_invite_rejected", {
          bootstrap_intent_id: intentId,
          reason_code: unavailableReason,
        });
        if (intent.invite_attempt_count >= 5) {
          intent.status = "denied";
          intent.denied_at = at;
          intent.updated_at = at;
          intent.record_revision += 1;
        }
        return { ok: false, code: "BOOTSTRAP_APPROVAL_UNAVAILABLE", status: 403, category: "unavailable" };
      }

      const reservationId = "whr7res_" + randomUUID();
      const enrollmentTxId = "whr7et_" + randomUUID();
      const bindingId = "whr7b_" + randomUUID();
      const authTxId = "whr7at_" + randomUUID();
      const rawCode = "whr7ac_" + randomBytes(32).toString("base64url");

      invite.registrations_reserved += 1;
      invite.record_revision += 1;

      const binding = {
        binding_id: bindingId,
        registration_id: null,
        registration_invite_id: invite.registration_invite_id,
        enrollment_tx_id: enrollmentTxId,
        bootstrap_intent_id: intentId,
        adapter_type: intent.adapter_type,
        proof_verifier_ref: null,
        proof_fingerprint: null,
        proof_identity_key: null,
        credential_generation: 1,
        binding_state: "provisional",
        capability_status: { ...DEFAULT_CAPABILITIES },
        legacy_migration: false,
        created_at: at,
        last_authenticated_at: null,
        record_revision: 1,
      };
      const reservation = {
        reservation_id: reservationId,
        enrollment_tx_id: enrollmentTxId,
        binding_id: bindingId,
        registration_invite_id: invite.registration_invite_id,
        bootstrap_intent_id: intentId,
        quota_epoch: invite.quota_epoch,
        status: "reserved",
        created_at: at,
        expires_at: nowIso(nowMs + 10 * 60 * 1000),
        record_revision: 1,
      };
      const enrollment = {
        enrollment_tx_id: enrollmentTxId,
        client_id: intent.client_id,
        redirect_uri: intent.redirect_uri,
        resource: intent.resource,
        scope: intent.scope,
        authorization_authority: intent.authorization_authority,
        code_challenge: intent.code_challenge,
        bootstrap_intent_id: intentId,
        reservation_id: reservationId,
        registration_id: null,
        binding_id: bindingId,
        oauth_grant_id: null,
        step: "WAITING_FIRST_INITIALIZE",
        created_at: at,
        expires_at: nowIso(nowMs + 10 * 60 * 1000),
        completed_at: null,
        status: "in_progress",
        record_revision: 1,
      };
      const authTx = {
        auth_transaction_id: authTxId,
        bootstrap_intent_id: intentId,
        enrollment_tx_id: enrollmentTxId,
        migration_auth_transaction_id: null,
        client_id: intent.client_id,
        code_hash: sha256Hex(rawCode),
        code_challenge: intent.code_challenge,
        code_challenge_method: "S256",
        redirect_uri: intent.redirect_uri,
        resource: intent.resource,
        scope: intent.scope,
        authorization_authority: intent.authorization_authority,
        status: "code_issued",
        created_at: at,
        expires_at: nowIso(nowMs + 600 * 1000),
        consumed_at: null,
        record_revision: 1,
      };

      store.installationBindings.push(binding);
      store.registrationReservations.push(reservation);
      store.enrollmentTransactions.push(enrollment);
      store.authorizationTransactions.push(authTx);

      intent.bootstrap_method = "invite_post";
      intent.registration_invite_id = invite.registration_invite_id;
      intent.invite_fingerprint = invite.credential_fingerprint;
      intent.invite_verified_at = at;
      intent.bootstrap_verified_at = at;
      intent.quota_epoch = invite.quota_epoch;
      intent.reservation_id = reservationId;
      intent.enrollment_tx_id = enrollmentTxId;
      intent.binding_id = bindingId;
      intent.authorization_transaction_id = authTxId;
      intent.quota_reserved_at = at;
      intent.code_issued_at = at;
      intent.status = "code_issued";
      intent.updated_at = at;
      intent.record_revision += 1;

      this._audit(store, "bootstrap_invite_verified", {
        bootstrap_intent_id: intentId,
        registration_invite_id: invite.registration_invite_id,
        invite_fingerprint: invite.credential_fingerprint,
      });
      this._audit(store, "bootstrap_quota_reserved", {
        bootstrap_intent_id: intentId,
        registration_invite_id: invite.registration_invite_id,
        quota_epoch: invite.quota_epoch,
        reservation_id: reservationId,
      });
      if (legacyTransport) {
        this._audit(store, "bootstrap_legacy_transport_used", { bootstrap_intent_id: intentId });
      }
      this._audit(store, "oauth_auth_code_issued", {
        bootstrap_intent_id: intentId,
        auth_transaction_id: authTxId,
        client_id: intent.client_id,
        enrollment_tx_id: enrollmentTxId,
      });

      return {
        ok: true,
        rawCode,
        intent,
        authTransaction: authTx,
        redirectUri: intent.redirect_uri,
        state: intent.oauth_state,
        issuer: intent.authorization_authority,
      };
    });

    if (!result.ok) {
      const error = makeError(result.code, result.code, result.status);
      error.category = result.category;
      throw error;
    }
    return result;
  }

  async confirmBootstrapSupersessionAndIssueCode({
    intentId,
    browserSessionHash,
    csrfToken,
    browserContext = null,
    origin = null,
  }) {
    const csrfHash = (typeof csrfToken === "string" && csrfToken.length > 0) ? sha256Hex(csrfToken) : null;
    const result = await this._mutate((store) => {
      const intent = store.bootstrapIntents.find((i) => i.bootstrap_intent_id === intentId);
      const nowMs = this.now();
      const at = nowIso(nowMs);
      if (!intent) return { ok: false, code: "BOOTSTRAP_INTENT_NOT_FOUND", status: 404 };
      if (intent.status !== "bootstrap_verified" || !intent.recovery_candidate_intent_id) {
        return { ok: false, code: "BOOTSTRAP_SUPERSESSION_NOT_PENDING", status: 409 };
      }
      if (new Date(intent.expires_at).getTime() <= nowMs) {
        intent.status = "expired";
        intent.expired_at = at;
        intent.updated_at = at;
        intent.record_revision += 1;
        return { ok: false, code: "BOOTSTRAP_INTENT_EXPIRED", status: 410 };
      }
      const authCheck = evaluateBrowserAuthorityContext({
        browserContext,
        origin,
        intent,
        browserSessionHash,
        csrfHash,
        legacyTransport: false,
      });
      if (!authCheck.ok) {
        return { ok: false, code: authCheck.code, status: authCheck.status, category: "security" };
      }

      const prior = store.bootstrapIntents.find(
        (i) => i.bootstrap_intent_id === intent.recovery_candidate_intent_id
      );
      if (!prior ||
          prior.registration_invite_id !== intent.registration_invite_id ||
          prior.client_id !== intent.client_id ||
          prior.redirect_uri !== intent.redirect_uri ||
          prior.resource !== intent.resource ||
          prior.authorization_authority !== intent.authorization_authority ||
          prior.scope !== intent.scope ||
          prior.registration_id) {
        return { ok: false, code: "BOOTSTRAP_SUPERSESSION_LINEAGE_INVALID", status: 409 };
      }

      const invite = store.registrationInvites.find(
        (i) => i.registration_invite_id === intent.registration_invite_id
      );
      if (!invite || invite.status !== "active") {
        return { ok: false, code: "BOOTSTRAP_APPROVAL_UNAVAILABLE", status: 403 };
      }
      const supersession = evaluateBootstrapSupersession(store, prior, invite);
      if (!supersession.exactLineage) {
        return { ok: false, code: "BOOTSTRAP_SUPERSESSION_LINEAGE_INVALID", status: 409 };
      }
      if (!supersession.safe) {
        return { ok: false, code: "BOOTSTRAP_ACTIVATION_IN_PROGRESS", status: 409 };
      }
      const {
        reservation,
        enrollment,
        binding,
        authorization: priorAuth,
        grant: priorGrant,
        safeCode,
        safeGrant,
      } = supersession;

      if (safeCode) {
        priorAuth.status = "superseded";
        priorAuth.record_revision += 1;
      }
      if (safeGrant) {
        priorGrant.status = "superseded_lost_response";
        priorGrant.record_revision += 1;
      }

      const authTxId = "whr7at_" + randomUUID();
      const rawCode = "whr7ac_" + randomBytes(32).toString("base64url");
      const authTx = {
        auth_transaction_id: authTxId,
        bootstrap_intent_id: intent.bootstrap_intent_id,
        enrollment_tx_id: enrollment.enrollment_tx_id,
        migration_auth_transaction_id: null,
        client_id: intent.client_id,
        code_hash: sha256Hex(rawCode),
        code_challenge: intent.code_challenge,
        code_challenge_method: "S256",
        redirect_uri: intent.redirect_uri,
        resource: intent.resource,
        scope: intent.scope,
        authorization_authority: intent.authorization_authority,
        status: "code_issued",
        created_at: at,
        expires_at: nowIso(nowMs + 600 * 1000),
        consumed_at: null,
        record_revision: 1,
      };

      reservation.bootstrap_intent_id = intent.bootstrap_intent_id;
      reservation.record_revision += 1;
      enrollment.bootstrap_intent_id = intent.bootstrap_intent_id;
      enrollment.client_id = intent.client_id;
      enrollment.redirect_uri = intent.redirect_uri;
      enrollment.resource = intent.resource;
      enrollment.scope = intent.scope;
      enrollment.authorization_authority = intent.authorization_authority;
      enrollment.code_challenge = intent.code_challenge;
      enrollment.oauth_grant_id = null;
      enrollment.status = "in_progress";
      enrollment.record_revision += 1;
      binding.bootstrap_intent_id = intent.bootstrap_intent_id;
      binding.proof_identity_key = null;
      binding.record_revision += 1;

      prior.status = "superseded";
      prior.superseded_at = at;
      prior.superseded_by_intent_id = intent.bootstrap_intent_id;
      prior.updated_at = at;
      prior.record_revision += 1;

      intent.bootstrap_method = "invite_post";
      intent.quota_epoch = invite.quota_epoch;
      intent.reservation_id = reservation.reservation_id;
      intent.enrollment_tx_id = enrollment.enrollment_tx_id;
      intent.binding_id = binding.binding_id;
      intent.authorization_transaction_id = authTxId;
      intent.quota_reserved_at = prior.quota_reserved_at || at;
      intent.code_issued_at = at;
      intent.status = "code_issued";
      intent.updated_at = at;
      intent.record_revision += 1;
      store.authorizationTransactions.push(authTx);

      this._audit(store, "bootstrap_superseded", {
        prior_bootstrap_intent_id: prior.bootstrap_intent_id,
        bootstrap_intent_id: intent.bootstrap_intent_id,
        reservation_id: reservation.reservation_id,
      });
      this._audit(store, "oauth_auth_code_issued", {
        bootstrap_intent_id: intent.bootstrap_intent_id,
        auth_transaction_id: authTxId,
        client_id: intent.client_id,
        enrollment_tx_id: enrollment.enrollment_tx_id,
      });

      return {
        ok: true,
        rawCode,
        intent,
        authTransaction: authTx,
        redirectUri: intent.redirect_uri,
        state: intent.oauth_state,
        issuer: intent.authorization_authority,
      };
    });
    if (!result.ok) throw makeError(result.code, result.code, result.status);
    return result;
  }

  async cancelBootstrapIntent({ intentId, browserSessionHash, csrfToken, browserContext = null, origin = null }) {
    const csrfHash = (typeof csrfToken === "string" && csrfToken.length > 0) ? sha256Hex(csrfToken) : null;
    const result = await this._mutate((store) => {
      const intent = store.bootstrapIntents.find((i) => i.bootstrap_intent_id === intentId);
      if (!intent) return { ok: false, code: "BOOTSTRAP_INTENT_NOT_FOUND", status: 404 };
      const authCheck = evaluateBrowserAuthorityContext({
        browserContext,
        origin,
        intent,
        browserSessionHash,
        csrfHash,
        legacyTransport: false,
      });
      if (!authCheck.ok) {
        return { ok: false, code: authCheck.code, status: authCheck.status, category: "security" };
      }
      if (!["awaiting_bootstrap", "bootstrap_verified"].includes(intent.status)) {
        return { ok: false, code: "BOOTSTRAP_INTENT_NOT_LIVE", status: 409 };
      }
      const at = nowIso(this.now());
      intent.status = "denied";
      intent.denied_at = at;
      intent.updated_at = at;
      intent.record_revision += 1;
      this._audit(store, "bootstrap_denied", { bootstrap_intent_id: intentId });
      return {
        ok: true,
        clientId: intent.client_id,
        redirectUri: intent.redirect_uri,
        state: intent.oauth_state,
        issuer: intent.authorization_authority,
      };
    });
    if (!result.ok) throw makeError(result.code, result.code, result.status);
    return result;
  }

  async issueMigrationTicket({
    registrationId,
    bindingId,
    ownerActionId,
    allowedAdapterType = "CLAUDE_OAUTH_DCR_GRANT",
    ttlMs = 3600 * 1000,
  }) {
    if (!ownerActionId) {
      throw makeError("MIGRATION_UNAUTHORIZED", "Owner action ID required", 403);
    }
    return this._mutate((store) => {
      const binding = store.installationBindings.find((b) => b.binding_id === bindingId);
      if (!binding || binding.binding_state !== "migration_unbound") {
        throw makeError("INVALID_MIGRATION_BINDING", "Binding not in migration_unbound state", 400);
      }
      const at = nowIso(this.now());
      const nowMs = this.now();
      const ticketId = "whr7mt_" + randomUUID();
      const ticket = {
        migration_ticket_id: ticketId,
        owner_action_id: ownerActionId,
        registration_id: registrationId,
        binding_id: bindingId,
        allowed_adapter_type: allowedAdapterType,
        nonce_challenge: randomBytes(16).toString("hex"),
        status: "issued",
        created_at: at,
        expires_at: nowIso(nowMs + ttlMs),
        claimed_at: null,
        migration_auth_transaction_id: null,
        record_revision: 1,
      };
      store.migrationAuthorizations.push(ticket);
      this._audit(store, "MIGRATION_TICKET_ISSUED", {
        migration_ticket_id: ticketId,
        registration_id: registrationId,
        binding_id: bindingId,
        owner_action_id: ownerActionId,
      });
      return ticket;
    });
  }

  async createAuthorizationTransaction({
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod = "S256",
    state = null,
    scope = "winhelm:mcp",
    resource = null,
    migrationTicket = null,
    migrationAuthTransactionId = null,
    inviteCredential = null,
    adapterType = "CLAUDE_OAUTH_DCR_GRANT",
  }) {
    if (!resource || typeof resource !== "string") {
      throw makeError("INVALID_TARGET", "OAuth resource is required", 400);
    }
    if (codeChallengeMethod !== "S256") {
      throw makeError("INVALID_REQUEST", "Only S256 code challenge method supported", 400);
    }
    if (!codeChallenge || typeof codeChallenge !== "string" || codeChallenge.length < 43) {
      throw makeError("INVALID_REQUEST", "Valid code_challenge required", 400);
    }

    if (!migrationTicket && !migrationAuthTransactionId) {
      if (!inviteCredential) {
        throw makeError("INSTALLATION_BINDING_REQUIRED", "Registration invite required", 401);
      }
      let authorizationAuthority;
      try {
        authorizationAuthority = new URL(resource).origin;
      } catch {
        throw makeError("INVALID_TARGET", "OAuth resource is malformed", 400);
      }
      if (resource !== `${authorizationAuthority}/mcp`) {
        throw makeError("INVALID_TARGET", "OAuth resource must be the protected /mcp resource", 400);
      }
      const browserSecret = randomBytes(32).toString("base64url");
      const csrfSecret = randomBytes(32).toString("base64url");
      const browserSessionHash = sha256Hex(browserSecret);
      const intent = await this.createBootstrapIntent({
        clientId,
        redirectUri,
        codeChallenge,
        codeChallengeMethod,
        state: state ?? "legacy-store-compat",
        scope,
        resource,
        authorizationAuthority,
        browserSessionHash,
        csrfTokenHash: sha256Hex(csrfSecret),
        adapterType,
      });
      return this.verifyBootstrapInviteAndIssueCode({
        intentId: intent.bootstrap_intent_id,
        browserSessionHash,
        csrfToken: csrfSecret,
        origin: authorizationAuthority,
        inviteCredential,
        legacyTransport: true,
      });
    }

    return this._mutate((store) => {
      const client = findActiveOAuthClient(store, clientId);
      if (!client) {
        throw makeError("INVALID_CLIENT", "Unknown or inactive client_id", 400);
      }
      if (!matchesRedirectUri(client.redirect_uris, redirectUri)) {
        throw makeError("INVALID_REQUEST", "redirect_uri not registered for this client", 400);
      }

      const at = nowIso(this.now());
      const nowMs = this.now();
      const rawCode = "whr7ac_" + randomBytes(32).toString("base64url");
      const codeHash = sha256Hex(rawCode);
      const authTxId = "whr7at_" + randomUUID();

      // Branch A2: Migration Continuation Mode
      if (migrationAuthTransactionId) {
        const mat = store.migrationAuthTransactions.find(
          (m) => m.migration_auth_transaction_id === migrationAuthTransactionId && m.status === "claimed"
        );
        if (!mat || new Date(mat.expires_at).getTime() < nowMs) {
          throw makeError("INVALID_REQUEST", "Migration continuation transaction invalid or expired", 400);
        }
        if (mat.client_id !== clientId || mat.redirect_uri !== redirectUri) {
          throw makeError("INVALID_REQUEST", "Migration continuation parameters mismatch", 400);
        }
        if ((mat.resource ?? null) !== (resource ?? null)) {
          throw makeError("INVALID_TARGET", "Migration continuation resource mismatch", 400);
        }

        const authTx = {
          auth_transaction_id: authTxId,
          enrollment_tx_id: null,
          migration_auth_transaction_id: migrationAuthTransactionId,
          client_id: clientId,
          code_hash: codeHash,
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
          redirect_uri: redirectUri,
          resource: resource ?? null,
          status: "code_issued",
          created_at: at,
          expires_at: nowIso(nowMs + 600 * 1000),
          consumed_at: null,
          record_revision: 1,
        };
        store.authorizationTransactions.push(authTx);

        this._audit(store, "oauth_auth_code_issued", {
          auth_transaction_id: authTxId,
          client_id: clientId,
          migration_auth_transaction_id: migrationAuthTransactionId,
          resource: resource ?? null,
        });

        return {
          rawCode,
          authTransaction: authTx,
          redirectUri,
          state,
          migrationAuthTransactionId,
        };
      }

      // Branch A: Migration Mode
      if (migrationTicket) {
        const ticket = store.migrationAuthorizations.find(
          (t) => t.migration_ticket_id === migrationTicket
        );
        if (!ticket || ticket.status !== "issued" || new Date(ticket.expires_at).getTime() < nowMs) {
          if (ticket && ticket.status === "consumed") {
            this._audit(store, "oauth_migration_ticket_replay_rejected", {
              migration_ticket_id: ticket.migration_ticket_id,
            });
          }
          throw makeError("INVALID_REQUEST", "Migration ticket is invalid, expired, or already claimed.", 400);
        }

        const migrationAuthTxId = "whr7mat_" + randomUUID();
        const mat = {
          migration_auth_transaction_id: migrationAuthTxId,
          migration_ticket_id: ticket.migration_ticket_id,
          registration_id: ticket.registration_id,
          binding_id: ticket.binding_id,
          owner_action_id: ticket.owner_action_id,
          client_id: clientId,
          redirect_uri: redirectUri,
          resource: resource ?? null,
          code_challenge: codeChallenge,
          adapter_type: ticket.allowed_adapter_type || adapterType,
          auth_transaction_id: authTxId,
          status: "claimed",
          created_at: at,
          expires_at: nowIso(nowMs + 10 * 60 * 1000),
          completed_at: null,
          record_revision: 1,
        };

        ticket.status = "consumed";
        ticket.claimed_at = at;
        ticket.migration_auth_transaction_id = migrationAuthTxId;
        ticket.record_revision += 1;

        const authTx = {
          auth_transaction_id: authTxId,
          enrollment_tx_id: null,
          migration_auth_transaction_id: migrationAuthTxId,
          client_id: clientId,
          code_hash: codeHash,
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
          redirect_uri: redirectUri,
          resource: resource ?? null,
          status: "code_issued",
          created_at: at,
          expires_at: nowIso(nowMs + 600 * 1000),
          consumed_at: null,
          record_revision: 1,
        };

        store.migrationAuthTransactions.push(mat);
        store.authorizationTransactions.push(authTx);

        this._audit(store, "oauth_migration_ticket_claimed", {
          migration_ticket_id: ticket.migration_ticket_id,
          migration_auth_transaction_id: migrationAuthTxId,
        });
        this._audit(store, "oauth_auth_code_issued", {
          auth_transaction_id: authTxId,
          client_id: clientId,
        });

        return {
          rawCode,
          authTransaction: authTx,
          redirectUri,
          state,
          migrationAuthTransactionId: migrationAuthTxId,
        };
      }

      // Generic enrollment is handled before this lock through the bootstrap-intent
      // state machine. Reaching this branch indicates a programmer error.
      throw makeError("BOOTSTRAP_STATE_MACHINE_REQUIRED", "Generic OAuth must use bootstrap intent admission", 500);
    });
  }

  async exchangeAuthorizationCode({
    code,
    clientId,
    redirectUri,
    codeVerifier,
    resource = null,
    clientAuthenticated = false,
  }) {
    if (!code || typeof code !== "string") {
      throw makeError("INVALID_GRANT", "Authorization code required", 400);
    }
    if (!resource || typeof resource !== "string") {
      throw makeError("INVALID_TARGET", "OAuth resource is required for authorization-code exchange", 400);
    }
    const codeHash = sha256Hex(code);

    return this._mutate((store) => {
      const nowMs = this.now();
      const at = nowIso(nowMs);
      const tx = store.authorizationTransactions.find((t) => t.code_hash === codeHash);

      if (!tx || new Date(tx.expires_at).getTime() < nowMs) {
        throw makeError("INVALID_GRANT", "Authorization code invalid or expired", 400);
      }

      // Reject replay before bootstrap live-state validation so consumed codes remain single-use and diagnostic-stable.
      if (tx.status === "consumed") {
        this._audit(store, "oauth_code_replay_rejected", {
          auth_transaction_id: tx.auth_transaction_id,
        });
        throw makeError("INVALID_GRANT", "Authorization code already consumed", 400);
      }

      if (tx.status !== "code_issued") {
        throw makeError("INVALID_GRANT", "Authorization code not in code_issued state", 400);
      }


      let bootstrapIntent = null;
      if (tx.bootstrap_intent_id) {
        bootstrapIntent = store.bootstrapIntents.find((i) => i.bootstrap_intent_id === tx.bootstrap_intent_id);
        if (!bootstrapIntent ||
            bootstrapIntent.authorization_transaction_id !== tx.auth_transaction_id ||
            bootstrapIntent.enrollment_tx_id !== tx.enrollment_tx_id ||
            bootstrapIntent.client_id !== tx.client_id ||
            bootstrapIntent.redirect_uri !== tx.redirect_uri ||
            bootstrapIntent.resource !== tx.resource ||
            bootstrapIntent.scope !== tx.scope ||
            bootstrapIntent.authorization_authority !== tx.authorization_authority ||
            bootstrapIntent.code_challenge !== tx.code_challenge ||
            bootstrapIntent.status !== "code_issued") {
          throw makeError("INVALID_GRANT", "Bootstrap authorization lineage mismatch", 400);
        }
      }

      if (tx.client_id !== clientId) {
        throw makeError("INVALID_GRANT", "client_id mismatch", 400);
      }

      const tokenClient = findActiveOAuthClient(store, clientId);
      if (!tokenClient) throw makeError("INVALID_CLIENT", "Unknown or inactive client_id", 401);
      if (tokenClient.client_type === "STATIC_CONFIDENTIAL_GEMINI" && !clientAuthenticated) {
        throw makeError("INVALID_CLIENT", "Static confidential client authentication required", 401);
      }

      if (tx.redirect_uri !== redirectUri) {
        throw makeError("INVALID_GRANT", "redirect_uri mismatch", 400);
      }

      if ((tx.resource ?? null) !== (resource ?? null)) {
        throw makeError("INVALID_TARGET", "OAuth resource does not match authorization transaction", 400);
      }

      if (!verifyPkce(codeVerifier, tx.code_challenge, tx.code_challenge_method)) {
        throw makeError("INVALID_GRANT", "Invalid PKCE code_verifier", 400);
      }

      // Mark code consumed
      tx.status = "consumed";
      tx.consumed_at = at;
      tx.record_revision += 1;
      if (bootstrapIntent) {
        bootstrapIntent.status = "code_redeemed";
        bootstrapIntent.code_redeemed_at = at;
        bootstrapIntent.updated_at = at;
        bootstrapIntent.record_revision += 1;
      }

      // Generate plaintext token pair
      const accessToken = "whr7at_" + randomBytes(32).toString("base64url");
      const refreshToken = "whr7rt_" + randomBytes(32).toString("base64url");
      const accessTokenHash = sha256Hex(accessToken);
      const refreshTokenHash = sha256Hex(refreshToken);
      const grantId = "whr7g_" + randomUUID();
      const tokenFamilyId = "whr7tf_" + randomUUID();
      const accessTokenExpiresAt = nowIso(nowMs + 3600 * 1000);
      const refreshTokenExpiresAt = nowIso(nowMs + 30 * 24 * 3600 * 1000);

      if (tx.migration_auth_transaction_id) {
        const mat = store.migrationAuthTransactions.find(
          (m) => m.migration_auth_transaction_id === tx.migration_auth_transaction_id
        );
        if (!mat) throw makeError("INVALID_MIGRATION", "Migration transaction missing", 500);

        const binding = store.installationBindings.find((b) => b.binding_id === mat.binding_id);
        if (!binding) throw makeError("INVALID_MIGRATION", "Migrated binding missing", 500);

        const grantIdentityKey = deriveGrantIdentityKey(grantId, mat.migration_auth_transaction_id);

        binding.proof_identity_key = grantIdentityKey;
        binding.credential_generation = 1;
        binding.binding_state = "active";
        binding.last_authenticated_at = at;
        binding.record_revision += 1;

        mat.status = "completed";
        mat.completed_at = at;
        mat.record_revision += 1;

        const grant = {
          oauth_grant_id: grantId,
          enrollment_tx_id: null,
          migration_auth_transaction_id: mat.migration_auth_transaction_id,
          grant_identity_key: grantIdentityKey,
          binding_id: binding.binding_id,
          client_id: clientId,
          resource: tx.resource ?? null,
          token_family_id: tokenFamilyId,
          refresh_generation: 1,
          current_access_token_hash: accessTokenHash,
          current_refresh_token_hash: refreshTokenHash,
          previous_refresh_token_hash: null,
          previous_refresh_expires_at: null,
          access_token_expires_at: accessTokenExpiresAt,
          refresh_token_expires_at: refreshTokenExpiresAt,
          status: "active",
          created_at: at,
          last_used_at: null,
          revoked_at: null,
          revocation_reason: null,
          record_revision: 1,
        };

        store.oauthGrants.push(grant);

        this._audit(store, "oauth_code_exchanged", {
          oauth_grant_id: grantId,
          binding_id: binding.binding_id,
          client_id: clientId,
        });

        return {
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: 3600,
          token_type: "Bearer",
          scope: "winhelm:mcp",
        };
      }

      // Generic Enrollment
      const enrollmentTx = store.enrollmentTransactions.find(
        (e) => e.enrollment_tx_id === tx.enrollment_tx_id
      );
      const grantIdentityKey = deriveGrantIdentityKey(grantId, tx.enrollment_tx_id);
      let bindingId = enrollmentTx?.binding_id;

      if (!bindingId) {
        bindingId = "whr7b_" + randomUUID();
        const binding = {
          binding_id: bindingId,
          registration_id: null,
          enrollment_tx_id: tx.enrollment_tx_id,
          adapter_type: "CLAUDE_OAUTH_DCR_GRANT",
          proof_verifier_ref: null,
          proof_fingerprint: null,
          proof_identity_key: grantIdentityKey,
          credential_generation: 1,
          binding_state: "provisional",
          capability_status: { ...DEFAULT_CAPABILITIES },
          legacy_migration: false,
          created_at: at,
          last_authenticated_at: null,
          record_revision: 1,
        };
        store.installationBindings.push(binding);
        if (enrollmentTx) enrollmentTx.binding_id = bindingId;
      } else {
        const b = store.installationBindings.find((x) => x.binding_id === bindingId);
        if (b) {
          b.proof_identity_key = grantIdentityKey;
          b.record_revision += 1;
        }
      }

      if (enrollmentTx) {
        enrollmentTx.oauth_grant_id = grantId;
        enrollmentTx.record_revision += 1;
      }

      const grant = {
        oauth_grant_id: grantId,
        bootstrap_intent_id: tx.bootstrap_intent_id ?? null,
        enrollment_tx_id: tx.enrollment_tx_id,
        migration_auth_transaction_id: null,
        grant_identity_key: grantIdentityKey,
        binding_id: bindingId,
        client_id: clientId,
        redirect_uri: tx.redirect_uri,
        resource: tx.resource ?? null,
        scope: tx.scope ?? "winhelm:mcp",
        authorization_authority: tx.authorization_authority ?? null,
        token_family_id: tokenFamilyId,
        refresh_generation: 1,
        current_access_token_hash: accessTokenHash,
        current_refresh_token_hash: refreshTokenHash,
        previous_refresh_token_hash: null,
        previous_refresh_expires_at: null,
        access_token_expires_at: accessTokenExpiresAt,
        refresh_token_expires_at: refreshTokenExpiresAt,
        status: "active",
        created_at: at,
        last_used_at: null,
        revoked_at: null,
        revocation_reason: null,
        record_revision: 1,
      };

      store.oauthGrants.push(grant);
      if (bootstrapIntent) {
        const enrollment = store.enrollmentTransactions.find((e) => e.enrollment_tx_id === tx.enrollment_tx_id);
        const binding = store.installationBindings.find((b) => b.binding_id === bindingId);
        if (!enrollment || enrollment.bootstrap_intent_id !== bootstrapIntent.bootstrap_intent_id ||
            !binding || binding.bootstrap_intent_id !== bootstrapIntent.bootstrap_intent_id) {
          throw makeError("INVALID_GRANT", "Bootstrap grant lineage mismatch", 400);
        }
        enrollment.oauth_grant_id = grantId;
        enrollment.record_revision += 1;
        bootstrapIntent.oauth_grant_id = grantId;
        bootstrapIntent.status = "installation_pending";
        bootstrapIntent.installation_pending_at = at;
        bootstrapIntent.updated_at = at;
        bootstrapIntent.record_revision += 1;
      }

      this._audit(store, "oauth_code_exchanged", {
        bootstrap_intent_id: tx.bootstrap_intent_id ?? null,
        oauth_grant_id: grantId,
        binding_id: bindingId,
        client_id: clientId,
      });

      return {
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_in: 3600,
        token_type: "Bearer",
        scope: "winhelm:mcp",
      };
    });
  }

  async refreshTokensPathwayA({ refreshToken, resource = null, clientId = null, clientAuthenticated = false }) {
    if (!refreshToken || typeof refreshToken !== "string") {
      throw makeError("INVALID_GRANT", "Refresh token required", 400);
    }
    const reqHash = sha256Hex(refreshToken);

    return this._mutate((store) => {
      const nowMs = this.now();
      const at = nowIso(nowMs);

      // Find grant matching current or previous hash
      const grant = store.oauthGrants.find(
        (g) => g.current_refresh_token_hash === reqHash || g.previous_refresh_token_hash === reqHash
      );

      if (!grant) {
        // Unknown refresh token -> Replay attack detection!
        return {
          status: 400,
          revoked: true,
          error: "invalid_grant",
          description: "Invalid refresh token",
        };
      }

      const grantClient = findActiveOAuthClient(store, grant.client_id);
      if (!grantClient) throw makeError("INVALID_CLIENT", "OAuth client is no longer active", 401);
      if (grantClient.client_type === "STATIC_CONFIDENTIAL_GEMINI") {
        if (clientId !== grant.client_id || !clientAuthenticated) {
          throw makeError("INVALID_CLIENT", "Static confidential client authentication required for refresh", 401);
        }
      } else if (clientId !== null && clientId !== undefined && clientId !== grant.client_id) {
        throw makeError("INVALID_CLIENT", "client_id mismatch", 401);
      }

      if (resource !== null && resource !== undefined && (grant.resource ?? null) !== resource) {
        throw makeError("INVALID_TARGET", "OAuth resource does not match refresh token grant", 400);
      }

      if (grant.status === "revoked") {
        throw makeError("INVALID_GRANT", "Token family revoked", 400);
      }

      // ROUTINE ROTATION: matches current_refresh_token_hash
      if (grant.current_refresh_token_hash === reqHash) {
        if (new Date(grant.refresh_token_expires_at).getTime() < nowMs) {
          throw makeError("INVALID_GRANT", "Refresh token expired", 400);
        }

        const sourceGen = grant.refresh_generation;
        const newGen = sourceGen + 1;
        const freshAt = "whr7at_" + randomBytes(32).toString("base64url");
        const freshRt = "whr7rt_" + randomBytes(32).toString("base64url");

        grant.previous_refresh_token_hash = grant.current_refresh_token_hash;
        grant.previous_refresh_expires_at = nowIso(nowMs + 30 * 1000); // 30s grace window
        grant.current_access_token_hash = sha256Hex(freshAt);
        grant.current_refresh_token_hash = sha256Hex(freshRt);
        grant.access_token_expires_at = nowIso(nowMs + 3600 * 1000);
        grant.refresh_token_expires_at = nowIso(nowMs + 30 * 24 * 3600 * 1000);
        grant.refresh_generation = newGen;
        grant.record_revision += 1;

        const refreshTxId = "whr7rtx_" + randomUUID();
        const refreshTx = {
          refresh_tx_id: refreshTxId,
          oauth_grant_id: grant.oauth_grant_id,
          token_family_id: grant.token_family_id,
          request_refresh_token_hash: reqHash,
          source_generation: sourceGen,
          committed_generation: newGen,
          recovery_generation: null,
          status: "committed",
          created_at: at,
          committed_at: at,
          retry_window_expires_at: nowIso(nowMs + 30 * 1000),
          completed_at: null,
          record_revision: 1,
        };
        store.refreshTransactions.push(refreshTx);

        this._audit(store, "oauth_refresh_rotated", {
          oauth_grant_id: grant.oauth_grant_id,
          refresh_tx_id: refreshTxId,
          generation: newGen,
        });

        return {
          status: 200,
          access_token: freshAt,
          refresh_token: freshRt,
          expires_in: 3600,
          token_type: "Bearer",
          refresh_generation: newGen,
          oauth_grant_id: grant.oauth_grant_id,
        };
      }

      // LOST RESPONSE RECOVERY CHECK: matches previous_refresh_token_hash
      if (
        grant.previous_refresh_token_hash === reqHash &&
        grant.previous_refresh_expires_at &&
        nowMs <= new Date(grant.previous_refresh_expires_at).getTime()
      ) {
        // Find refresh transaction for source generation
        const refreshTx = store.refreshTransactions.find(
          (t) => t.oauth_grant_id === grant.oauth_grant_id && t.request_refresh_token_hash === reqHash
        );

        // Check if AT_{N+1} was already used on /mcp
        if (grant.last_used_at !== null) {
          const lastUsedMs = new Date(grant.last_used_at).getTime();
          const committedMs = refreshTx ? new Date(refreshTx.committed_at).getTime() : 0;
          if (lastUsedMs >= committedMs) {
            // Replay detected! Legitimate client received N+1; N is replayed
            grant.status = "revoked";
            grant.revocation_reason = "REFRESH_REPLAY_DETECTED";
            grant.current_access_token_hash = null;
            grant.current_refresh_token_hash = null;
            grant.previous_refresh_token_hash = null;
            grant.record_revision += 1;

            const binding = store.installationBindings.find((b) => b.binding_id === grant.binding_id);
            if (binding) {
              binding.binding_state = "revoked";
              binding.record_revision += 1;
            }

            this._audit(store, "oauth_refresh_replay_revocation", {
              oauth_grant_id: grant.oauth_grant_id,
              binding_id: grant.binding_id,
            });

            return {
              status: 400,
              revoked: true,
              bindingId: grant.binding_id,
              error: "invalid_grant",
              description: "Refresh token replay detected. Token family revoked.",
            };
          }
        }

        // Check Anti-Rotation Amplification Guard
        if (refreshTx && refreshTx.recovery_generation !== null) {
          this._audit(store, "oauth_refresh_recovery_limit_exceeded", {
            oauth_grant_id: grant.oauth_grant_id,
            refresh_tx_id: refreshTx.refresh_tx_id,
          });
          throw makeError("INVALID_GRANT", "Refresh recovery limit reached for this generation", 400);
        }

        // First recovery retry: generate N+2 successor
        const recoveryGen = grant.refresh_generation + 1; // N+2
        const freshAt = "whr7at_" + randomBytes(32).toString("base64url");
        const freshRt = "whr7rt_" + randomBytes(32).toString("base64url");

        grant.current_access_token_hash = sha256Hex(freshAt);
        grant.current_refresh_token_hash = sha256Hex(freshRt);
        grant.access_token_expires_at = nowIso(nowMs + 3600 * 1000);
        grant.refresh_token_expires_at = nowIso(nowMs + 30 * 24 * 3600 * 1000);
        grant.refresh_generation = recoveryGen;
        grant.record_revision += 1;

        if (refreshTx) {
          refreshTx.recovery_generation = recoveryGen;
          refreshTx.status = "recovery_committed";
          refreshTx.record_revision += 1;
        }

        this._audit(store, "oauth_refresh_recovery_issued", {
          oauth_grant_id: grant.oauth_grant_id,
          recovery_generation: recoveryGen,
        });

        return {
          status: 200,
          access_token: freshAt,
          refresh_token: freshRt,
          expires_in: 3600,
          token_type: "Bearer",
          refresh_generation: recoveryGen,
          oauth_grant_id: grant.oauth_grant_id,
        };
      }

      // Outside grace window or replayed
      grant.status = "revoked";
      grant.revocation_reason = "REFRESH_REPLAY_DETECTED";
      grant.current_access_token_hash = null;
      grant.current_refresh_token_hash = null;
      grant.previous_refresh_token_hash = null;
      grant.record_revision += 1;

      const binding = store.installationBindings.find((b) => b.binding_id === grant.binding_id);
      if (binding) {
        binding.binding_state = "revoked";
        binding.record_revision += 1;
      }

      this._audit(store, "oauth_refresh_replay_revocation", {
        oauth_grant_id: grant.oauth_grant_id,
        binding_id: grant.binding_id,
      });

      return {
        status: 400,
        revoked: true,
        bindingId: grant.binding_id,
        error: "invalid_grant",
        description: "Refresh token replay detected. Token family revoked.",
      };
    });
  }

  async revokeOAuthToken({ token }) {
    if (!token || typeof token !== "string") {
      return { revoked: false };
    }
    const tokenHash = sha256Hex(token);

    return this._mutate((store) => {
      const grant = store.oauthGrants.find(
        (g) =>
          g.current_access_token_hash === tokenHash ||
          g.current_refresh_token_hash === tokenHash ||
          g.previous_refresh_token_hash === tokenHash
      );

      if (!grant) {
        return { revoked: false };
      }

      const at = nowIso(this.now());
      grant.status = "revoked";
      grant.revocation_reason = "EXPLICIT_REVOCATION";
      grant.revoked_at = at;
      grant.current_access_token_hash = null;
      grant.current_refresh_token_hash = null;
      grant.previous_refresh_token_hash = null;
      grant.record_revision += 1;

      const binding = store.installationBindings.find((b) => b.binding_id === grant.binding_id);
      if (binding) {
        binding.binding_state = "revoked";
        binding.record_revision += 1;
      }

      this._audit(store, "oauth_grant_revoked", {
        oauth_grant_id: grant.oauth_grant_id,
        binding_id: grant.binding_id,
      });

      return { revoked: true, bindingId: grant.binding_id };
    });
  }

  async authenticateOAuthAccessToken({ accessToken, expectedResource = null }) {
    if (!accessToken || typeof accessToken !== "string") {
      throw makeError("INSTALLATION_BINDING_REQUIRED", "Access token required", 401);
    }
    if (!expectedResource || typeof expectedResource !== "string") {
      throw makeError("INSTALLATION_BINDING_INVALID", "Expected OAuth resource is required", 401);
    }
    const tokenHash = sha256Hex(accessToken);
    const store = await this._read();
    const nowMs = this.now();

    const grant = store.oauthGrants.find((g) => g.current_access_token_hash === tokenHash);
    if (!grant) {
      // Check if it belongs to a superseded grant
      const superseded = store.oauthGrants.find(
        (g) => g.status === "superseded_lost_response" && g.current_access_token_hash === tokenHash
      );
      if (superseded) {
        throw makeError("INSTALLATION_BINDING_INVALID", "Grant superseded by reauthorization", 401);
      }
      throw makeError("INSTALLATION_BINDING_REQUIRED", "Access token not found or invalid", 401);
    }

    if (grant.status === "superseded_lost_response") {
      throw makeError("INSTALLATION_BINDING_INVALID", "Grant superseded by reauthorization", 401);
    }
    if (grant.status === "revoked") {
      throw makeError("INSTALLATION_BINDING_REVOKED", "Grant revoked", 403);
    }
    if (grant.status !== "active") {
      throw makeError("INSTALLATION_BINDING_INVALID", "Grant not active", 401);
    }
    if (new Date(grant.access_token_expires_at).getTime() < nowMs) {
      throw makeError("INSTALLATION_BINDING_INVALID", "Access token expired", 401);
    }

    if ((grant.resource ?? null) !== expectedResource) {
      throw makeError("INSTALLATION_BINDING_INVALID", "OAuth access token resource mismatch", 401);
    }

    const binding = store.installationBindings.find((b) => b.binding_id === grant.binding_id);
    if (!binding) {
      throw makeError("INSTALLATION_BINDING_INVALID", "Linked installation binding missing", 401);
    }
    if (binding.binding_state === "revoked") {
      throw makeError("INSTALLATION_BINDING_REVOKED", "Installation binding revoked", 403);
    }
    if (binding.binding_state === "disabled") {
      throw makeError("INSTALLATION_BINDING_DISABLED", "Installation binding disabled", 403);
    }

    let registration = null;
    if (binding.registration_id) {
      registration = store.registeredInstallations.find((r) => r.registration_id === binding.registration_id);
    }

    let bootstrapIntent = null;
    let enrollment = null;
    let reservation = null;
    if (!registration && grant.bootstrap_intent_id) {
      bootstrapIntent = store.bootstrapIntents.find((i) =>
        i.bootstrap_intent_id === grant.bootstrap_intent_id &&
        i.binding_id === binding.binding_id &&
        i.enrollment_tx_id === grant.enrollment_tx_id &&
        i.oauth_grant_id === grant.oauth_grant_id
      );
      enrollment = store.enrollmentTransactions.find((e) =>
        e.enrollment_tx_id === grant.enrollment_tx_id &&
        e.bootstrap_intent_id === grant.bootstrap_intent_id &&
        e.binding_id === binding.binding_id &&
        e.oauth_grant_id === grant.oauth_grant_id
      );
      reservation = bootstrapIntent?.reservation_id
        ? store.registrationReservations.find((r) =>
            r.reservation_id === bootstrapIntent.reservation_id &&
            r.bootstrap_intent_id === bootstrapIntent.bootstrap_intent_id &&
            r.enrollment_tx_id === grant.enrollment_tx_id &&
            r.binding_id === binding.binding_id)
        : null;
      if (!bootstrapIntent || !enrollment || !reservation) {
        throw makeError("BOOTSTRAP_LINEAGE_INVALID", "Provisional OAuth lineage incomplete", 409);
      }
    }

    return { grant, binding, registration, bootstrapIntent, enrollment, reservation };
  }

  async beginOAuthInitialize({
    bindingId,
    oauthGrantId,
    bootstrapIntentId,
    enrollmentTxId,
    reservationId,
    quotaEpoch,
  }) {
    return this._mutate((store) => {
      const lineage = resolveOAuthActivationLineage(store, {
        bindingId, oauthGrantId, bootstrapIntentId, enrollmentTxId, reservationId, quotaEpoch,
      });
      const { binding, grant, intent, enrollment, reservation, invite } = lineage;
      if (intent.status !== "installation_pending" ||
          grant.status !== "active" || grant.last_used_at !== null ||
          binding.binding_state !== "provisional" || binding.registration_id !== null ||
          enrollment.status !== "in_progress" ||
          invite.status !== "active") {
        throw makeError("OAUTH_ACTIVATION_LINEAGE_INVALID", "OAuth activation lineage is not begin-eligible", 409);
      }
      const state = reservationLifecycleState(reservation);
      if (state !== "reserved" || reservation.activation_attempt_id) {
        throw makeError("BOOTSTRAP_ACTIVATION_IN_PROGRESS", "OAuth activation already started or is uncertain", 409);
      }

      const at = nowIso(this.now());
      const activationAttemptId = "whr7act_" + randomUUID();
      reservation.status = "initializing";
      reservation.activation_attempt_id = activationAttemptId;
      reservation.activation_started_at = at;
      reservation.activation_updated_at = at;
      reservation.activation_uncertain_reason = null;
      reservation.record_revision += 1;

      enrollment.activation_attempt_id = activationAttemptId;
      enrollment.activation_state = "initializing";
      enrollment.record_revision += 1;

      this._audit(store, "oauth_initialize_activation_started", {
        activation_attempt_id: activationAttemptId,
        bootstrap_intent_id: bootstrapIntentId,
        oauth_grant_id: oauthGrantId,
        binding_id: bindingId,
        enrollment_tx_id: enrollmentTxId,
        reservation_id: reservationId,
        quota_epoch: quotaEpoch,
      });

      return {
        activationAttemptId,
        bindingId,
        oauthGrantId,
        bootstrapIntentId,
        enrollmentTxId,
        reservationId,
        quotaEpoch,
        state: "initializing",
      };
    });
  }

  async markOAuthInitializeCommitting({
    bindingId,
    oauthGrantId,
    bootstrapIntentId,
    enrollmentTxId,
    reservationId,
    quotaEpoch,
    activationAttemptId,
  }) {
    return this._mutate((store) => {
      const lineage = resolveOAuthActiveAttemptLineage(store, {
        bindingId, oauthGrantId, bootstrapIntentId, enrollmentTxId, reservationId,
        activationAttemptId, quotaEpoch,
      });
      const { reservation, enrollment } = lineage;
      const state = reservationLifecycleState(reservation);
      if (state === "committing") return { changed: false, state, ...lineage };
      if (state !== "initializing") {
        const code = state === "uncertain" ? "OAUTH_ACTIVATION_UNCERTAIN" : "OAUTH_ACTIVATION_STALE";
        throw makeError(code, "Activation is not eligible to enter commit", 409);
      }
      const at = nowIso(this.now());
      reservation.status = "committing";
      reservation.activation_updated_at = at;
      reservation.record_revision += 1;
      enrollment.activation_state = "committing";
      enrollment.record_revision += 1;
      this._audit(store, "oauth_initialize_activation_committing", {
        activation_attempt_id: activationAttemptId,
        bootstrap_intent_id: bootstrapIntentId,
        oauth_grant_id: oauthGrantId,
        reservation_id: reservationId,
      });
      return { changed: true, state: "committing" };
    });
  }

  async markOAuthInitializeUncertain({
    bindingId,
    oauthGrantId,
    bootstrapIntentId,
    enrollmentTxId,
    reservationId,
    quotaEpoch,
    activationAttemptId,
    reason = "ambiguous_core_outcome",
  }) {
    return this._mutate((store) => {
      const lineage = resolveOAuthActiveAttemptLineage(store, {
        bindingId, oauthGrantId, bootstrapIntentId, enrollmentTxId, reservationId,
        activationAttemptId, quotaEpoch,
      });
      const { reservation, enrollment } = lineage;
      const state = reservationLifecycleState(reservation);
      if (OAUTH_ACTIVATION_TERMINAL_STATES.has(state)) {
        return { changed: false, state };
      }
      if (state === "uncertain") return { changed: false, state };
      if (!OAUTH_ACTIVATION_BLOCKING_STATES.has(state)) {
        throw makeError("OAUTH_ACTIVATION_STALE", "Activation state is not uncertainty-eligible", 409);
      }
      const at = nowIso(this.now());
      const reasonCode = String(reason || "ambiguous_core_outcome").slice(0, 128);
      reservation.status = "uncertain";
      reservation.activation_updated_at = at;
      reservation.activation_uncertain_reason = reasonCode;
      reservation.record_revision += 1;
      enrollment.activation_state = "uncertain";
      enrollment.record_revision += 1;
      this._audit(store, "oauth_initialize_activation_uncertain", {
        activation_attempt_id: activationAttemptId,
        bootstrap_intent_id: bootstrapIntentId,
        oauth_grant_id: oauthGrantId,
        reservation_id: reservationId,
        reason: reasonCode,
      });
      return { changed: true, state: "uncertain" };
    });
  }

  async abortOAuthInitialize({
    bindingId,
    oauthGrantId,
    bootstrapIntentId,
    enrollmentTxId,
    reservationId,
    quotaEpoch,
    activationAttemptId,
    reason = "core_initialize_rejected",
  }) {
    return this._mutate((store) => {
      const lineage = resolveOAuthActiveAttemptLineage(store, {
        bindingId, oauthGrantId, bootstrapIntentId, enrollmentTxId, reservationId,
        activationAttemptId, quotaEpoch,
      });
      const { binding, grant, intent, enrollment, reservation, invite } = lineage;
      const state = reservationLifecycleState(reservation);
      if (state === "released") return { released: false, reason: "already_released" };
      if (state === "committed") return { released: false, reason: "already_committed" };
      if (state === "uncertain") {
        throw makeError("OAUTH_ACTIVATION_UNCERTAIN", "Uncertain activation cannot be auto-released", 409);
      }
      if (!["initializing", "committing"].includes(state)) {
        throw makeError("OAUTH_ACTIVATION_STALE", "Activation is not abort-eligible", 409);
      }

      const at = nowIso(this.now());
      const reasonCode = String(reason || "core_initialize_rejected").slice(0, 128);
      reservation.status = "released";
      reservation.released_at = at;
      reservation.release_reason = reasonCode;
      reservation.activation_terminal_at = at;
      reservation.activation_updated_at = at;
      reservation.record_revision += 1;
      if (reservation.quota_epoch === invite.quota_epoch && invite.registrations_reserved > 0) {
        invite.registrations_reserved -= 1;
        invite.record_revision += 1;
      }
      enrollment.status = "released";
      enrollment.activation_state = "released";
      enrollment.completed_at = at;
      enrollment.record_revision += 1;
      intent.status = "released";
      intent.released_at = at;
      intent.release_reason = reasonCode;
      intent.updated_at = at;
      intent.record_revision += 1;
      if (grant.status === "active") {
        grant.status = "expired_cleanup";
        grant.record_revision += 1;
      }
      if (binding.binding_state === "provisional") {
        binding.binding_state = "expired_cleanup";
        binding.record_revision += 1;
      }
      this._audit(store, "oauth_initialize_activation_aborted", {
        activation_attempt_id: activationAttemptId,
        bootstrap_intent_id: bootstrapIntentId,
        oauth_grant_id: oauthGrantId,
        binding_id: bindingId,
        reservation_id: reservationId,
        reason: reasonCode,
      });
      return { released: true, state: "released" };
    });
  }

  async touchOAuthGrantUsed(grantId) {
    return this._mutate((store) => {
      const grant = store.oauthGrants.find((g) => g.oauth_grant_id === grantId);
      if (grant) {
        grant.last_used_at = nowIso(this.now());
        grant.record_revision += 1;
      }
      return grant;
    });
  }

  async commitOAuthEnrollment(bindingIdOrOptions) {
    const options = typeof bindingIdOrOptions === "object" && bindingIdOrOptions !== null
      ? bindingIdOrOptions
      : { bindingId: bindingIdOrOptions };
    const bindingId = options.bindingId;
    const clientSnapshot = options.clientRegistrationSnapshot || null;
    const expectedActivation = {
      bindingId,
      oauthGrantId: options.oauthGrantId,
      bootstrapIntentId: options.bootstrapIntentId,
      enrollmentTxId: options.enrollmentTxId,
      reservationId: options.reservationId,
      quotaEpoch: options.quotaEpoch,
      activationAttemptId: options.activationAttemptId,
    };

    return this._mutate((store) => {
      const binding = store.installationBindings.find((b) => b.binding_id === bindingId);
      if (!binding) throw makeError("BINDING_NOT_FOUND", "Binding missing", 404);

      let reservation = null;
      let invite = null;
      let enrollmentTx = null;
      let bootstrapIntent = null;
      let grant = null;
      const isBootstrapOAuth = Boolean(binding.bootstrap_intent_id);

      if (isBootstrapOAuth) {
        const lineage = resolveOAuthActiveAttemptLineage(store, expectedActivation);
        reservation = lineage.reservation;
        invite = lineage.invite;
        enrollmentTx = lineage.enrollment;
        bootstrapIntent = lineage.intent;
        grant = lineage.grant;
        const activationState = reservationLifecycleState(reservation);

        if (binding.binding_state === "active" && binding.registration_id) {
          const registration = store.registeredInstallations.find((r) => r.registration_id === binding.registration_id);
          if (!registration || activationState !== "committed" ||
              bootstrapIntent.status !== "committed" ||
              bootstrapIntent.registration_id !== registration.registration_id ||
              enrollmentTx.status !== "completed" ||
              enrollmentTx.registration_id !== registration.registration_id) {
            throw makeError("OAUTH_ACTIVATION_STALE", "Committed activation lineage is inconsistent", 409);
          }
          return { binding, registration, grant, reservation, activationAttemptId: expectedActivation.activationAttemptId, recovered: true };
        }

        if (binding.binding_state !== "provisional" || binding.registration_id !== null ||
            bootstrapIntent.status !== "installation_pending" ||
            grant.status !== "active" ||
            enrollmentTx.status !== "in_progress" ||
            enrollmentTx.activation_attempt_id !== expectedActivation.activationAttemptId ||
            !["initializing", "committing"].includes(activationState)) {
          throw makeError("OAUTH_ACTIVATION_STALE", "Activation lineage is not commit-eligible", 409);
        }
      } else {
        if (binding.binding_state === "active" && binding.registration_id) {
          const registration = store.registeredInstallations.find((r) => r.registration_id === binding.registration_id);
          return { binding, registration };
        }
        reservation = store.registrationReservations.find(
          (r) => r.enrollment_tx_id === binding.enrollment_tx_id && reservationLifecycleState(r) === "reserved"
        );
        if (!reservation) throw makeError("RESERVATION_NOT_FOUND", "Active reservation missing", 409);
        invite = store.registrationInvites.find(
          (i) => i.registration_invite_id === reservation.registration_invite_id
        );
        if (!invite) throw makeError("INVITE_NOT_FOUND", "Registration invite missing", 404);
        enrollmentTx = store.enrollmentTransactions.find(
          (e) => e.enrollment_tx_id === binding.enrollment_tx_id
        );
      }
      if (!["active", "exhausted"].includes(invite.status)) {
        throw makeError("INVITE_NOT_ACTIVE", "Registration invite was explicitly disabled or revoked", 403);
      }
      if (reservation.quota_epoch !== undefined && reservation.quota_epoch !== invite.quota_epoch) {
        throw makeError("RESERVATION_EPOCH_STALE", "Registration reservation epoch is stale", 409);
      }
      if (invite.registrations_reserved <= 0) {
        throw makeError("RESERVATION_COUNTER_INVALID", "Reserved quota counter is invalid", 409);
      }
      if (invite.quota_epoch_max !== null &&
          invite.quota_epoch_used + invite.registrations_reserved > invite.quota_epoch_max) {
        throw makeError("QUOTA_INVARIANT_VIOLATION", "Registration quota invariant violated", 409);
      }

      const nowMs = this.now();
      const at = nowIso(nowMs);
      const registrationId = "whr7r_" + randomUUID();

      invite.quota_epoch_used += 1;
      invite.registrations_reserved -= 1;
      invite.registrations_lifetime += 1;
      invite.registrations_active += 1;
      if (invite.quota_epoch_max !== null && invite.quota_epoch_used >= invite.quota_epoch_max) {
        invite.status = "exhausted";
      }
      invite.record_revision += 1;

      const registration = {
        registration_id: registrationId,
        registration_invite_id: invite.registration_invite_id,
        created_at: at,
        status: "active",
        client_registration_snapshot: clientSnapshot,
        install_sequence: invite.registrations_lifetime,
        record_revision: 1,
        session_lease: {
          generation: 0,
          bound_session_id: null,
          bound_at: null,
          session_state: "idle",
          pending_init_id: null,
          pending_at: null,
          replacing_session_id: null,
        },
      };

      binding.registration_id = registrationId;
      binding.binding_state = "active";
      binding.last_authenticated_at = at;
      binding.record_revision += 1;

      if (Object.prototype.hasOwnProperty.call(reservation, "status")) reservation.status = "committed";
      if (Object.prototype.hasOwnProperty.call(reservation, "state")) reservation.state = "committed";
      if (isBootstrapOAuth) {
        reservation.activation_terminal_at = at;
        reservation.activation_updated_at = at;
      }
      reservation.record_revision += 1;

      if (enrollmentTx) {
        enrollmentTx.registration_id = registrationId;
        enrollmentTx.status = "completed";
        if (isBootstrapOAuth) enrollmentTx.activation_state = "committed";
        enrollmentTx.completed_at = at;
        enrollmentTx.record_revision += 1;
      }

      store.registeredInstallations.push(registration);

      if (bootstrapIntent) {
        bootstrapIntent.registration_id = registrationId;
        bootstrapIntent.status = "committed";
        bootstrapIntent.committed_at = at;
        bootstrapIntent.updated_at = at;
        bootstrapIntent.record_revision += 1;
      }

      this._audit(store, "ENROLLMENT_COMMITTED", {
        registration_id: registrationId,
        binding_id: binding.binding_id,
        registration_invite_id: invite.registration_invite_id,
      });

      return isBootstrapOAuth
        ? { binding, registration, grant, reservation, activationAttemptId: expectedActivation.activationAttemptId }
        : { binding, registration };
    });
  }

  async sweepExpired() {
    return this._mutate((store) => {
      const nowMs = this.now();
      const at = nowIso(nowMs);
      let sweptBootstrapIntents = 0;
      let sweptReservations = 0;
      let sweptIdempotency = 0;
      let sweptAuthCodes = 0;

      // 0. Expire bootstrap intents first so any linked quota reservation is released exactly once.
      for (const intent of store.bootstrapIntents) {
        if (!["created", "awaiting_bootstrap", "bootstrap_verified", "quota_reserved", "code_issued", "code_redeemed", "installation_pending"].includes(intent.status)) continue;
        if (new Date(intent.expires_at).getTime() > nowMs) continue;

        const reservation = intent.reservation_id
          ? store.registrationReservations.find((r) =>
              r.reservation_id === intent.reservation_id &&
              r.bootstrap_intent_id === intent.bootstrap_intent_id)
          : null;
        if (reservation && OAUTH_ACTIVATION_BLOCKING_STATES.has(reservationLifecycleState(reservation))) {
          this._audit(store, "bootstrap_expiry_deferred_for_activation", {
            bootstrap_intent_id: intent.bootstrap_intent_id,
            reservation_id: reservation.reservation_id,
            activation_attempt_id: reservation.activation_attempt_id ?? null,
            activation_state: reservationLifecycleState(reservation),
          });
          continue;
        }
        if (reservation && reservation.status === "reserved") {
          reservation.status = "expired";
          reservation.released_at = at;
          reservation.release_reason = "bootstrap_intent_expired";
          reservation.record_revision += 1;
          const invite = store.registrationInvites.find(
            (i) => i.registration_invite_id === reservation.registration_invite_id
          );
          if (invite && reservation.quota_epoch === invite.quota_epoch && invite.registrations_reserved > 0) {
            invite.registrations_reserved -= 1;
            invite.record_revision += 1;
          }
        }

        for (const grant of store.oauthGrants) {
          if (grant.bootstrap_intent_id === intent.bootstrap_intent_id && grant.status === "active") {
            grant.status = "expired_cleanup";
            grant.record_revision += 1;
          }
        }
        for (const binding of store.installationBindings) {
          if (binding.bootstrap_intent_id === intent.bootstrap_intent_id &&
              binding.registration_id === null &&
              binding.binding_state === "provisional") {
            binding.binding_state = "expired_cleanup";
            binding.record_revision += 1;
          }
        }
        for (const enrollment of store.enrollmentTransactions) {
          if (enrollment.bootstrap_intent_id === intent.bootstrap_intent_id &&
              enrollment.status === "in_progress") {
            enrollment.status = "terminal_failed";
            enrollment.record_revision += 1;
          }
        }
        for (const authTx of store.authorizationTransactions) {
          if (authTx.bootstrap_intent_id === intent.bootstrap_intent_id &&
              authTx.status === "code_issued") {
            authTx.status = "expired";
            authTx.record_revision += 1;
          }
        }

        intent.status = "expired";
        intent.expired_at = at;
        intent.updated_at = at;
        intent.release_reason = reservation ? "bootstrap_intent_expired" : intent.release_reason;
        intent.record_revision += 1;
        sweptBootstrapIntents += 1;
        this._audit(store, "bootstrap_expired", {
          bootstrap_intent_id: intent.bootstrap_intent_id,
          reservation_id: reservation?.reservation_id ?? null,
        });
      }

      // 1. Sweep expired reservations (10m TTL)
      for (const res of store.registrationReservations) {
        if (res.status === "reserved" && new Date(res.expires_at).getTime() <= nowMs) {
          res.status = "expired";
          res.record_revision += 1;
          sweptReservations += 1;

          const invite = store.registrationInvites.find(
            (i) => i.registration_invite_id === res.registration_invite_id
          );
          if (invite && invite.registrations_reserved > 0) {
            invite.registrations_reserved -= 1;
            invite.record_revision += 1;
          }

          const grants = store.oauthGrants.filter(
            (g) => g.enrollment_tx_id === res.enrollment_tx_id && g.last_used_at === null
          );
          for (const g of grants) {
            g.status = "expired_cleanup";
            g.record_revision += 1;
          }

          const bindings = store.installationBindings.filter(
            (b) => b.enrollment_tx_id === res.enrollment_tx_id && b.registration_id === null
          );
          for (const b of bindings) {
            b.binding_state = "expired_cleanup";
            b.record_revision += 1;
          }

          const txs = store.enrollmentTransactions.filter(
            (e) => e.enrollment_tx_id === res.enrollment_tx_id && e.status === "in_progress"
          );
          for (const tx of txs) {
            tx.status = "terminal_failed";
            tx.record_revision += 1;
          }
        }
      }

      // 2. Sweep expired DCR Idempotency Records (15m TTL)
      const prevIdempCount = store.dcrIdempotencyRecords.length;
      store.dcrIdempotencyRecords = store.dcrIdempotencyRecords.filter(
        (r) => new Date(r.expires_at).getTime() > nowMs
      );
      sweptIdempotency = prevIdempCount - store.dcrIdempotencyRecords.length;

      // 3. Sweep completed refresh transactions (after 30s grace window)
      for (const rtx of store.refreshTransactions) {
        if (
          (rtx.status === "committed" || rtx.status === "recovery_committed") &&
          new Date(rtx.retry_window_expires_at).getTime() <= nowMs
        ) {
          rtx.status = "completed";
          rtx.completed_at = at;
          rtx.record_revision += 1;
        }
      }

      // 4. Sweep expired authorization codes (120s TTL)
      const prevAuthCount = store.authorizationTransactions.length;
      store.authorizationTransactions = store.authorizationTransactions.filter(
        (a) => !(a.status === "code_issued" && new Date(a.expires_at).getTime() <= nowMs)
      );
      sweptAuthCodes = prevAuthCount - store.authorizationTransactions.length;

      return { sweptBootstrapIntents, sweptReservations, sweptIdempotency, sweptAuthCodes };
    });
  }
}

export function buildBrowserContext(req, authority) {
  const originHeader = typeof req?.headers?.origin === "string" ? req.headers.origin.trim() : null;
  const hostHeader = typeof req?.headers?.host === "string" ? req.headers.host.trim() : "";
  const secFetchSite = typeof req?.headers?.["sec-fetch-site"] === "string" ? req.headers["sec-fetch-site"].trim().toLowerCase() : null;
  const secFetchMode = typeof req?.headers?.["sec-fetch-mode"] === "string" ? req.headers["sec-fetch-mode"].trim().toLowerCase() : null;
  const secFetchDest = typeof req?.headers?.["sec-fetch-dest"] === "string" ? req.headers["sec-fetch-dest"].trim().toLowerCase() : null;
  const contentType = typeof req?.headers?.["content-type"] === "string" ? req.headers["content-type"].trim().toLowerCase() : "";

  return {
    configuredAuthority: authority || null,
    origin: originHeader,
    requestHost: hostHeader,
    secFetchSite,
    secFetchMode,
    secFetchDest,
    method: req?.method || "POST",
    contentType,
  };
}

export function evaluateBrowserAuthorityContext({
  browserContext = null,
  origin = null,
  intent = null,
  browserSessionHash = null,
  csrfHash = null,
  csrfToken = null,
  legacyTransport = false,
} = {}) {
  let ctx = browserContext;
  if (!ctx && origin !== null && origin !== undefined) {
    ctx = {
      origin: typeof origin === "string" ? origin : null,
      configuredAuthority: intent?.authorization_authority || (typeof origin === "string" ? origin : null),
      requestHost: null,
      secFetchSite: null,
      secFetchMode: null,
      secFetchDest: null,
      method: "POST",
      contentType: "application/x-www-form-urlencoded",
    };
  }

  // 1. Mandatory Session verification when intent is present (for all mutations including legacy)
  if (intent) {
    if (
      typeof browserSessionHash !== "string" ||
      browserSessionHash.trim().length === 0 ||
      !safeEqualHex(intent.browser_session_hash, browserSessionHash.trim())
    ) {
      return { ok: false, code: "BOOTSTRAP_SESSION_MISMATCH", status: 403, category: "security" };
    }
  }

  // 2. Mandatory CSRF verification (browser-hosted only: legacyTransport = false)
  if (!legacyTransport && intent) {
    const effectiveCsrfHash = csrfHash ?? (typeof csrfToken === "string" && csrfToken.trim().length > 0 ? sha256Hex(csrfToken.trim()) : null);
    if (
      typeof effectiveCsrfHash !== "string" ||
      effectiveCsrfHash.trim().length === 0 ||
      !safeEqualHex(intent.csrf_token_hash, effectiveCsrfHash.trim())
    ) {
      return { ok: false, code: "BOOTSTRAP_CSRF_MISMATCH", status: 403, category: "security" };
    }
  }

  // 3. Legacy transport check
  if (legacyTransport) {
    const checkOrigin = ctx?.origin ?? origin;
    if (intent && checkOrigin !== intent.authorization_authority) {
      return { ok: false, code: "BOOTSTRAP_AUTHORITY_MISMATCH", status: 403, category: "security" };
    }
    return { ok: true, proofType: "legacy_transport" };
  }

  if (!ctx) {
    return { ok: false, code: "BOOTSTRAP_CONTEXT_MISSING", status: 403, category: "security" };
  }

  const expectedAuthority = intent?.authorization_authority || ctx.configuredAuthority;
  if (!expectedAuthority) {
    return { ok: false, code: "BOOTSTRAP_AUTHORITY_INVALID", status: 403, category: "security" };
  }

  if (ctx.configuredAuthority && intent && ctx.configuredAuthority !== intent.authorization_authority) {
    return { ok: false, code: "BOOTSTRAP_AUTHORITY_MISMATCH", status: 403, category: "security" };
  }

  // Case A: Explicit Origin present
  const rawOrigin = ctx.origin;
  if (typeof rawOrigin === "string" && rawOrigin.trim().length > 0) {
    const trimmedOrigin = rawOrigin.trim();
    if (trimmedOrigin.toLowerCase() === "null") {
      return { ok: false, code: "BOOTSTRAP_ORIGIN_NULL", status: 403, category: "security" };
    }
    if (trimmedOrigin !== expectedAuthority) {
      return { ok: false, code: "BOOTSTRAP_ORIGIN_MISMATCH", status: 403, category: "security" };
    }
    return { ok: true, proofType: "exact_origin" };
  }

  // Case B: Origin absent (null, undefined, or empty string)
  if (ctx.method && ctx.method.toUpperCase() !== "POST") {
    return { ok: false, code: "BOOTSTRAP_METHOD_INVALID", status: 403, category: "security" };
  }

  const cType = String(ctx.contentType || "").toLowerCase();
  if (ctx.contentType && !cType.startsWith("application/x-www-form-urlencoded")) {
    return { ok: false, code: "BOOTSTRAP_CONTENT_TYPE_INVALID", status: 403, category: "security" };
  }

  let expectedHost = "";
  try {
    expectedHost = new URL(expectedAuthority).host.toLowerCase();
  } catch {
    return { ok: false, code: "BOOTSTRAP_AUTHORITY_INVALID", status: 403, category: "security" };
  }

  const requestHost = String(ctx.requestHost || "").trim().toLowerCase();
  if (!requestHost || requestHost !== expectedHost) {
    return { ok: false, code: "BOOTSTRAP_HOST_MISMATCH", status: 403, category: "security" };
  }

  if (!ctx.secFetchSite || String(ctx.secFetchSite).trim().toLowerCase() !== "same-origin") {
    return { ok: false, code: "BOOTSTRAP_FETCH_SITE_MISMATCH", status: 403, category: "security" };
  }

  if (!ctx.secFetchMode || String(ctx.secFetchMode).trim().toLowerCase() !== "navigate") {
    return { ok: false, code: "BOOTSTRAP_FETCH_MODE_MISMATCH", status: 403, category: "security" };
  }

  if (!ctx.secFetchDest || String(ctx.secFetchDest).trim().toLowerCase() !== "document") {
    return { ok: false, code: "BOOTSTRAP_FETCH_DEST_MISMATCH", status: 403, category: "security" };
  }

  return { ok: true, proofType: "fetch_metadata_same_origin" };
}

export const _test = {
  sha256,
  fingerprint,
  scryptVerifier,
  verifyScrypt,
  emptyStore,
  assertStoreShape,
  requireCapabilityObject,
};
