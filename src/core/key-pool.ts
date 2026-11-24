import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parseOAuthCredential } from "../aws-quick/oauth-client.js";
import { parseWebCurlOrCredential, serializeWebCredential } from "../aws-quick/web-client.js";
import type { BotQuotaView, QuickPlanQuotaView } from "../services/quota-service.js";
import { evictQuotaCachesForKey } from "../services/quota-service.js";
import { normalizeBaseModelId, redactSecrets } from "../utils/hash.js";
import { maskProxyUrl, validateProxyUrl } from "../utils/proxy-agent.js";
import { persistPoolConfigToEnvFile } from "./config.js";
import { SessionAffinityTable, type AffinityBindingView } from "./session-affinity.js";
import { GatewayError, type AutoDisabledState, type GatewayConfig, type LbStrategy } from "./types.js";

export interface KeyIdentitySummary {
  apiKeyName: string;
  userEmail?: string;
  displayName?: string;
  userId?: number;
  createdAt: string;
}

export type KeyAuthType = "oauth" | "cookie" | "outpost";

export function detectKeyAuthType(rawKey: string): KeyAuthType {
  const s = rawKey.trim();
  if (s.startsWith("oauth:")) return "oauth";
  if (s.startsWith("web:")) return "cookie";
  return "outpost";
}

export interface KeySlotStatus {
  slotId: string;
  label?: string;
  authType: KeyAuthType;
  addedAt: number;
  maskedKey: string;
  maskedProxy?: string;
  chatAgentId?: string;
  enabled: boolean;
  healthy: boolean;
  autoDisabledReason?: string;
  autoDisabledKind?: "quota" | "auth";
  /** ISO time the gateway expects to re-enable this key by itself (quota trips only). */
  autoRecoverAt?: string;
  apiPoolExhausted: boolean;
  autoPoolExhausted: boolean;
  activeInflight: number;
  stickySessions: number;
  cooldownRemainingMs: number;
  totalSelected: number;
  affinityHits: number;
  rateLimitHits: number;
  quotaExhaustedHits: number;
  authErrors: number;
  identity?: KeyIdentitySummary;
  quota?: QuickPlanQuotaView;
  bot?: BotQuotaView;
  cloudSessionCount?: number | null;
  tokenRemainingSec?: number | null;
  lastSyncError?: string;
  quotaUpdatedAt?: string;
}

interface InternalKeySlot {
  slotId: string;
  label?: string;
  authType: KeyAuthType;
  addedAt: number;
  rawKey: string;
  maskedKey: string;
  proxyUrl?: string;
  chatAgentId?: string;
  enabled: boolean;
  autoDisabledReason?: string;
  autoDisabledKind?: "quota" | "auth";
  autoResetAtMs?: number;
  apiPoolExhausted: boolean;
  autoPoolExhausted: boolean;
  activeInflight: number;
  cooldownUntil: number;
  connLimitCooldownUntil: number;
  consecutiveRateLimits: number;
  selected: number;
  affinityHits: number;
  rateLimits: number;
  quotaExhaustedHits: number;
  authErrors: number;
  identity?: KeyIdentitySummary;
  quota?: QuickPlanQuotaView;
  bot?: BotQuotaView;
  cloudSessionCount?: number | null;
  tokenRemainingSec?: number | null;
  lastSyncError?: string;
  quotaUpdatedAt?: string;
}

export interface KeyLease {
  apiKey: string;
  slotId: string;
  maskedKey: string;
  label?: string;
  proxyUrl?: string;
  chatAgentId?: string;
  viaAffinity: boolean;
  markSuccess: () => void;
  release: () => void;
}

export interface PoolRoutingSettings {
  lbStrategy: LbStrategy;
  sessionAffinityEnabled: boolean;
  sessionAffinityTtlSeconds: number;
  autoDisableExhaustedKeys: boolean;
  incognitoMode: boolean;
  autoEnsureCodingAgent: boolean;
  customAgentPrompt?: string;
  chatAgentId?: string;
}

const CHAT_AGENT_ID_RE = /^[A-Za-z0-9:_./-]{2,256}$/;

export function validateChatAgentId(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (!CHAT_AGENT_ID_RE.test(trimmed)) {
    throw new GatewayError(
      "Invalid chat_agent_id (must be 2-256 characters of letters, digits, or : _ . / - with no whitespace).",
      400,
      "invalid_chat_agent_id"
    );
  }
  return trimmed;
}

export function maskSecretKey(key: string): string {
  if (key.length <= 12) return "***";
  return `${key.slice(0, 8)}...${key.slice(-4)}`;
}

export function computeKeySlotId(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex").slice(0, 10);
}

export function classifyModelQuotaPool(requestedModel: string): "auto" | "api" {
  const base = normalizeBaseModelId(requestedModel || "auto");
  if (!base || base === "auto" || base === "default" || base.startsWith("quick-")) {
    return "auto";
  }
  return "api";
}

/**
 * Detect whether an upstream SDK / HTTP error means the account has run out of quota/money
 * (as opposed to a transient per-minute concurrency burst).
 */
export function isQuotaOrBillingExhaustedError(err: GatewayError): boolean {
  if (err.status === 402) return true;
  const hay = `${err.code} ${err.message}`.toLowerCase();
  return (
    hay.includes("insufficient_quota") ||
    hay.includes("out of credits") ||
    hay.includes("usage limit") ||
    hay.includes("spend limit") ||
    hay.includes("monthly limit") ||
    hay.includes("included usage") ||
    hay.includes("billing limit") ||
    hay.includes("payment required") ||
    hay.includes("plan limit")
  );
}

function getRemainingPercentForPool(quota: QuickPlanQuotaView | undefined, pool: "auto" | "api"): number | null {
  if (!quota) return null;
  const sessionRem = quota.sessionPool.remainingPercent;
  const apiRem = quota.premiumApiPool.remainingPercent;
  // Both auto and api requests consume the account's 5-hour short-term burst window.
  // Scoring by the tighter of (monthly remaining, short-term burst remaining) prevents
  // routing traffic onto an account whose monthly balance is high but burst window is ~95%+.
  if (sessionRem !== null && apiRem !== null) {
    return Math.min(sessionRem, apiRem);
  }
  const target = pool === "auto" ? sessionRem : apiRem;
  if (target !== null) return target;
  return quota.overallIncludedPlan.remainingPercent;
}

export const DEFAULT_MAX_INFLIGHT_PER_SLOT = 4;
export const DEFAULT_CONN_LIMIT_COOLDOWN_MS = 2_500;
export const DEFAULT_CONCURRENCY_WAIT_MS = 4_000;

export class UpstreamKeyPool {
  private readonly slots: InternalKeySlot[] = [];
  private readonly slotWaiters: Array<{ wake: () => void; canUse: (slot?: InternalKeySlot) => boolean }> = [];
  private readonly baseCooldownMs: number;
  private readonly maxInflightPerSlot: number;
  private readonly envFilePath?: string;
  private readonly identityFilePath?: string;
  private readonly savedIdentities: Record<string, { userEmail?: string; displayName?: string }> = Object.create(null);
  readonly affinityTable = new SessionAffinityTable();

  private lbStrategy: LbStrategy;
  private sessionAffinityEnabled: boolean;
  private sessionAffinityTtlMs: number;
  private autoDisableExhaustedKeys: boolean;
  private incognitoMode: boolean;
  private autoEnsureCodingAgent: boolean;
  private customAgentPrompt?: string;
  private chatAgentId?: string;
  private rrIndex = 0;

  constructor(config: Pick<
    GatewayConfig,
    | "quickTokens"
    | "disabledQuickTokens"
    | "keyLabels"
    | "keyProxies"
    | "keyAddedAt"
    | "keyAutoDisabled"
    | "keyCooldownMs"
    | "lbStrategy"
    | "sessionAffinityEnabled"
    | "sessionAffinityTtlMs"
    | "autoDisableExhaustedKeys"
    | "incognitoMode"
    | "envFilePath"
    | "dataDir"
  > & Partial<Pick<GatewayConfig, "chatAgentId" | "keyChatAgentIds" | "autoEnsureCodingAgent" | "customAgentPrompt">> & {
    maxInflightPerSlot?: number;
  }) {
    this.baseCooldownMs = config.keyCooldownMs;
    this.maxInflightPerSlot = Math.max(1, config.maxInflightPerSlot ?? DEFAULT_MAX_INFLIGHT_PER_SLOT);
    this.lbStrategy = config.lbStrategy;
    this.sessionAffinityEnabled = config.sessionAffinityEnabled;
    this.sessionAffinityTtlMs = config.sessionAffinityTtlMs;
    this.autoDisableExhaustedKeys = config.autoDisableExhaustedKeys;
    this.incognitoMode = config.incognitoMode !== false;
    this.autoEnsureCodingAgent = config.autoEnsureCodingAgent !== false;
    this.customAgentPrompt = config.customAgentPrompt?.trim() || undefined;
    this.chatAgentId = config.chatAgentId?.trim() || undefined;
    this.envFilePath = config.envFilePath;
    if (config.dataDir) {
      this.identityFilePath = path.join(config.dataDir, "account-identities.json");
      this.loadSavedIdentities();
    }

    const bootNow = Date.now();
    const totalBootKeys = config.quickTokens.length + config.disabledQuickTokens.length;
    let bootIdx = 0;
    for (const k of config.quickTokens) {
      const s = this.upsertInternal(k, true);
      if (config.keyLabels[s.slotId]) s.label = config.keyLabels[s.slotId];
      if (config.keyProxies?.[s.slotId]) s.proxyUrl = config.keyProxies[s.slotId];
      if (config.keyChatAgentIds?.[s.slotId]) s.chatAgentId = config.keyChatAgentIds[s.slotId];
      s.addedAt = config.keyAddedAt?.[s.slotId] ?? (bootNow - (totalBootKeys - bootIdx) * 1000);
      bootIdx += 1;
    }
    for (const k of config.disabledQuickTokens) {
      if (!this.slots.some((s) => s.rawKey === k)) {
        const s = this.upsertInternal(k, false);
        if (config.keyLabels[s.slotId]) s.label = config.keyLabels[s.slotId];
        if (config.keyProxies?.[s.slotId]) s.proxyUrl = config.keyProxies[s.slotId];
        if (config.keyChatAgentIds?.[s.slotId]) s.chatAgentId = config.keyChatAgentIds[s.slotId];
        s.addedAt = config.keyAddedAt?.[s.slotId] ?? (bootNow - (totalBootKeys - bootIdx) * 1000);
        bootIdx += 1;
        const saved = config.keyAutoDisabled?.[s.slotId];
        if (saved) {
          s.autoDisabledKind = saved.kind;
          s.autoDisabledReason = saved.reason || undefined;
          if (saved.resetAtMs) s.autoResetAtMs = saved.resetAtMs;
        }
      }
    }
  }

  private upsertInternal(rawKey: string, enabled: boolean, label?: string): InternalKeySlot {
    const trimmed = rawKey.trim();
    const existing = this.slots.find((s) => s.rawKey === trimmed);
    if (existing) {
      existing.enabled = enabled;
      if (enabled) {
        existing.autoDisabledReason = undefined;
        existing.autoDisabledKind = undefined;
      }
      if (label !== undefined) existing.label = label.trim() || undefined;
      return existing;
    }
    const slotId = computeKeySlotId(trimmed);
    const authType = detectKeyAuthType(trimmed);
    let initialIdentity: KeyIdentitySummary | undefined;
    const savedId = this.savedIdentities[slotId];
    if (authType === "oauth") {
      const parsedOAuth = parseOAuthCredential(trimmed);
      if (parsedOAuth?.email || parsedOAuth?.name || savedId?.userEmail || savedId?.displayName) {
        initialIdentity = {
          apiKeyName: "oauth-pkce (90d)",
          ...(parsedOAuth?.email || savedId?.userEmail ? { userEmail: parsedOAuth?.email || savedId?.userEmail } : {}),
          ...(parsedOAuth?.name || savedId?.displayName ? { displayName: parsedOAuth?.name || savedId?.displayName } : {}),
          createdAt: new Date().toISOString(),
        };
      }
    } else if (savedId?.userEmail || savedId?.displayName) {
      initialIdentity = {
        apiKeyName: authType === "cookie" ? "web-cookie" : "local-outpost",
        ...(savedId.userEmail ? { userEmail: savedId.userEmail } : {}),
        ...(savedId.displayName ? { displayName: savedId.displayName } : {}),
        createdAt: new Date().toISOString(),
      };
    }
    const slot: InternalKeySlot = {
      slotId,
      ...(label?.trim() ? { label: label.trim() } : {}),
      authType,
      addedAt: Date.now(),
      rawKey: trimmed,
      maskedKey: maskSecretKey(trimmed),
      enabled,
      apiPoolExhausted: false,
      autoPoolExhausted: false,
      activeInflight: 0,
      cooldownUntil: 0,
      connLimitCooldownUntil: 0,
      consecutiveRateLimits: 0,
      selected: 0,
      affinityHits: 0,
      rateLimits: 0,
      quotaExhaustedHits: 0,
      authErrors: 0,
      ...(initialIdentity ? { identity: initialIdentity } : {}),
    };
    this.slots.push(slot);
    return slot;
  }

  private loadSavedIdentities(): void {
    if (!this.identityFilePath) return;
    try {
      const raw = fs.readFileSync(this.identityFilePath, "utf8");
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        for (const [k, v] of Object.entries(parsed)) {
          if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
          if (v && typeof v === "object") {
            const rec = v as Record<string, unknown>;
            this.savedIdentities[k] = {
              ...(typeof rec.userEmail === "string" && rec.userEmail.trim() ? { userEmail: rec.userEmail.trim() } : {}),
              ...(typeof rec.displayName === "string" && rec.displayName.trim() ? { displayName: rec.displayName.trim() } : {}),
            };
          }
        }
      }
    } catch {
      // File may not exist on first boot
    }
  }

  private persistSavedIdentities(): void {
    if (!this.identityFilePath) return;
    try {
      const dir = path.dirname(this.identityFilePath);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const tmp = `${this.identityFilePath}.tmp.${process.pid}`;
      fs.writeFileSync(tmp, JSON.stringify(this.savedIdentities, null, 2), { encoding: "utf8", mode: 0o600 });
      fs.renameSync(tmp, this.identityFilePath);
    } catch {
      // Non-fatal persistence failure
    }
  }

  private persist(): void {
    const keyLabels: Record<string, string> = {};
    const keyProxies: Record<string, string> = {};
    const keyChatAgentIds: Record<string, string> = {};
    const keyAddedAt: Record<string, number> = {};
    for (const s of this.slots) {
      if (s.label) keyLabels[s.slotId] = s.label;
      if (s.proxyUrl) keyProxies[s.slotId] = s.proxyUrl;
      if (s.chatAgentId) keyChatAgentIds[s.slotId] = s.chatAgentId;
      if (s.addedAt) keyAddedAt[s.slotId] = s.addedAt;
    }
    const keyAutoDisabled: Record<string, AutoDisabledState> = {};
    for (const s of this.slots) {
      if (!s.enabled && s.autoDisabledKind && s.autoDisabledReason) {
        keyAutoDisabled[s.slotId] = {
          kind: s.autoDisabledKind,
          reason: s.autoDisabledReason,
          ...(s.autoResetAtMs ? { resetAtMs: s.autoResetAtMs } : {})
        };
      }
    }
    persistPoolConfigToEnvFile(this.envFilePath, {
      activeKeys: this.slots.filter((s) => s.enabled).map((s) => s.rawKey),
      disabledKeys: this.slots.filter((s) => !s.enabled).map((s) => s.rawKey),
      keyLabels,
      keyProxies,
      chatAgentId: this.chatAgentId ?? "",
      keyChatAgentIds,
      keyAddedAt,
      keyAutoDisabled,
      lbStrategy: this.lbStrategy,
      sessionAffinityEnabled: this.sessionAffinityEnabled,
      sessionAffinityTtlMs: this.sessionAffinityTtlMs,
      autoDisableExhaustedKeys: this.autoDisableExhaustedKeys,
      incognitoMode: this.incognitoMode,
      autoEnsureCodingAgent: this.autoEnsureCodingAgent,
      customAgentPrompt: this.customAgentPrompt ?? ""
    });
  }

  getSettings(): PoolRoutingSettings {
    return {
      lbStrategy: this.lbStrategy,
      sessionAffinityEnabled: this.sessionAffinityEnabled,
      sessionAffinityTtlSeconds: Math.round(this.sessionAffinityTtlMs / 1000),
      autoDisableExhaustedKeys: this.autoDisableExhaustedKeys,
      incognitoMode: this.incognitoMode,
      autoEnsureCodingAgent: this.autoEnsureCodingAgent,
      ...(this.customAgentPrompt ? { customAgentPrompt: this.customAgentPrompt } : {}),
      ...(this.chatAgentId ? { chatAgentId: this.chatAgentId } : {})
    };
  }

  updateSettings(patch: Partial<PoolRoutingSettings>): void {
    if (patch.lbStrategy) this.lbStrategy = patch.lbStrategy;
    if (typeof patch.sessionAffinityEnabled === "boolean") {
      this.sessionAffinityEnabled = patch.sessionAffinityEnabled;
      if (!patch.sessionAffinityEnabled) this.affinityTable.clearAll();
    }
    if (typeof patch.sessionAffinityTtlSeconds === "number" && patch.sessionAffinityTtlSeconds >= 10) {
      this.sessionAffinityTtlMs = patch.sessionAffinityTtlSeconds * 1000;
    }
    if (typeof patch.autoDisableExhaustedKeys === "boolean") {
      this.autoDisableExhaustedKeys = patch.autoDisableExhaustedKeys;
    }
    if (typeof patch.incognitoMode === "boolean") {
      this.incognitoMode = patch.incognitoMode;
    }
    if (typeof patch.autoEnsureCodingAgent === "boolean") {
      this.autoEnsureCodingAgent = patch.autoEnsureCodingAgent;
    }
    if (typeof patch.customAgentPrompt === "string") {
      this.customAgentPrompt = patch.customAgentPrompt.trim().slice(0, 4000) || undefined;
    }
    if (typeof patch.chatAgentId === "string") {
      this.chatAgentId = validateChatAgentId(patch.chatAgentId);
    }
    this.persist();
  }

  allManagedKeys(): Array<{ slotId: string; rawKey: string; enabled: boolean; label?: string; proxyUrl?: string; chatAgentId?: string }> {
    this.reviveCycleResetAccounts();
    return this.slots.map((s) => ({
      slotId: s.slotId,
      rawKey: s.rawKey,
      enabled: s.enabled,
      ...(s.label ? { label: s.label } : {}),
      ...(s.proxyUrl ? { proxyUrl: s.proxyUrl } : {}),
      ...(s.chatAgentId ? { chatAgentId: s.chatAgentId } : {}),
    }));
  }

  proxyUrlForKey(rawKey: string): string | undefined {
    return this.slots.find((s) => s.rawKey === rawKey)?.proxyUrl;
  }

  enabledKeyCount(): number {
    this.reviveCycleResetAccounts();
    return this.slots.filter((s) => s.enabled).length;
  }

  activeInflightForSlot(slotId: string): number {
    return this.slots.find((s) => s.slotId === slotId)?.activeInflight ?? 0;
  }

  private reviveCycleResetAccounts(): void {
    const now = Date.now();
    let changed = false;
    for (const s of this.slots) {
      // Only quota trips self-heal on the billing reset; an auth failure needs an explicit re-check.
      if (!s.enabled && s.autoDisabledReason && s.autoDisabledKind === "quota" && s.autoResetAtMs && now >= s.autoResetAtMs) {
        s.enabled = true;
        s.autoDisabledReason = undefined;
        s.autoDisabledKind = undefined;
        s.autoResetAtMs = undefined;
        s.apiPoolExhausted = false;
        s.autoPoolExhausted = false;
        changed = true;
      }
    }
    if (changed) this.persist();
  }

  private isSlotPoolExhausted(slot: InternalKeySlot, targetPool: "auto" | "api"): boolean {
    const flagged = targetPool === "auto" ? slot.autoPoolExhausted : slot.apiPoolExhausted;
    return flagged && !slot.quota?.onDemandSpend.enabled;
  }

  private isSlotEligibleForPool(slot: InternalKeySlot, targetPool: "auto" | "api", now: number): boolean {
    if (!slot.enabled) return false;
    if (slot.cooldownUntil > now) return false;
    if (this.isSlotPoolExhausted(slot, targetPool)) return false;
    return true;
  }

  isKeyUsable(rawKey: string, requestedModel = "auto"): boolean {
    this.reviveCycleResetAccounts();
    const slot = this.slots.find((s) => s.rawKey === rawKey);
    if (!slot) return true;
    const pool = classifyModelQuotaPool(requestedModel);
    return this.isSlotEligibleForPool(slot, pool, Date.now());
  }

  leaseSpecificKey(rawKey: string, viaAffinity = false): KeyLease {
    const slot = this.slots.find((s) => s.rawKey === rawKey);
    if (slot) {
      slot.selected += 1;
      if (viaAffinity) slot.affinityHits += 1;
      slot.activeInflight += 1;
    }
    let released = false;
    return {
      apiKey: rawKey,
      slotId: slot?.slotId ?? "direct",
      maskedKey: slot?.maskedKey ?? maskSecretKey(rawKey),
      ...(slot?.label ? { label: slot.label } : {}),
      ...(slot?.proxyUrl ? { proxyUrl: slot.proxyUrl } : {}),
      ...(slot?.chatAgentId ? { chatAgentId: slot.chatAgentId } : {}),
      viaAffinity,
      markSuccess: () => {
        if (slot) slot.consecutiveRateLimits = 0;
      },
      release: () => {
        if (released) return;
        released = true;
        if (slot && slot.activeInflight > 0) slot.activeInflight -= 1;
        this.notifySlotAvailable(slot);
      }
    };
  }

  private notifySlotAvailable(releasedSlot?: InternalKeySlot, maxWake = 1): void {
    let woken = 0;
    for (let i = 0; i < this.slotWaiters.length && woken < maxWake; ) {
      const w = this.slotWaiters[i]!;
      if (w.canUse(releasedSlot)) {
        this.slotWaiters.splice(i, 1);
        w.wake();
        woken += 1;
      } else {
        i += 1;
      }
    }
  }

  /**
   * Read-only pick of one enabled upstream key for catalog lookups (`/v1/models`, admin model list).
   * Unlike `leaseKey` it does not count as a selection, bind affinity, occupy a concurrency slot,
   * or fail with a quota error just because the pool is busy.
   */
  peekKeyForCatalog(): string {
    this.reviveCycleResetAccounts();
    const slot = this.slots.find((x) => x.enabled);
    if (!slot) {
      throw new GatewayError("No enabled upstream AWS Quick credentials available.", 503, "no_enabled_keys");
    }
    return slot.rawKey;
  }

  /**
   * Lease an optimal upstream AWS Quick credential after client authentication has already succeeded.
   * Always selects from the managed pool (1h sticky affinity); caller tokens are never used upstream.
   */
  leaseKey(
    requestedModel = "auto",
    excludeKeys?: ReadonlySet<string>,
    conversationKey?: string
  ): KeyLease {
    this.reviveCycleResetAccounts();

    // Never use caller tokens upstream; always pick from the managed credential pool.
    if (this.slots.length === 0) {
      throw new GatewayError("All upstream AWS Quick accounts are currently disabled or unconfigured.", 503, "no_enabled_keys");
    }
    return this.pickFromPool(requestedModel, excludeKeys, conversationKey);
  }

  /**
   * Async concurrency-aware lease: prefers accounts below `maxInflightPerSlot` (4, leaving 1 WS
   * headroom below AWS Quick's 5-connection hard limit). If every usable account is currently full,
   * performs a bounded soft-wait (default 4s, bounded queue) for a slot to free up instead of firing
   * a doomed 5th/6th WebSocket that triggers LimitExceededException / ThrottlingException.
   */
  async leaseKeyWithWait(
    requestedModel = "auto",
    excludeKeys?: ReadonlySet<string>,
    conversationKey?: string,
    opts?: { maxWaitMs?: number; signal?: AbortSignal },
  ): Promise<KeyLease> {
    this.reviveCycleResetAccounts();
    if (this.slots.length === 0) {
      throw new GatewayError("All upstream AWS Quick accounts are currently disabled or unconfigured.", 503, "no_enabled_keys");
    }

    const maxWaitMs = Math.max(0, opts?.maxWaitMs ?? DEFAULT_CONCURRENCY_WAIT_MS);
    const deadline = Date.now() + maxWaitMs;
    const targetPool = classifyModelQuotaPool(requestedModel);
    let hasWaited = false;

    while (true) {
      if (opts?.signal?.aborted) {
        throw new GatewayError("Request aborted while waiting for an upstream slot.", 499, "client_aborted");
      }
      const now = Date.now();
      for (const s of this.slots) {
        if (s.cooldownUntil > 0 && s.cooldownUntil <= now) s.cooldownUntil = 0;
        if (s.connLimitCooldownUntil > 0 && s.connLimitCooldownUntil <= now) s.connLimitCooldownUntil = 0;
      }
      const enabledSlots = this.slots.filter((s) => s.enabled && !excludeKeys?.has(s.rawKey));
      if (enabledSlots.length === 0) {
        throw new GatewayError("No enabled upstream AWS Quick credentials available.", 503, "no_enabled_keys");
      }
      const usableSlots = enabledSlots.filter((s) => !this.isSlotPoolExhausted(s, targetPool));
      if (usableSlots.length === 0) {
        throw new GatewayError(
          `All enabled AWS Quick accounts have exhausted their '${targetPool}' quota.`,
          429,
          "quota_exhausted",
        );
      }

      const hasCapacity = usableSlots.some(
        (s) => s.cooldownUntil === 0 && s.activeInflight < this.maxInflightPerSlot,
      );
      if (hasCapacity) {
        return this.pickFromPool(requestedModel, excludeKeys, conversationKey);
      }

      // If no account has inflight capacity (or all are briefly cooling down), check wait budget.
      const remainingMs = deadline - Date.now();
      const maxQueue = Math.max(4, usableSlots.length * this.maxInflightPerSlot);
      if (remainingMs <= 0 || (!hasWaited && this.slotWaiters.length >= maxQueue)) {
        // Only fall through to pickFromPool if all accounts are in long cooldown AND at least one
        // has inflight headroom (< maxInflightPerSlot); pickFromPool also enforces < maxInflightPerSlot.
        const anyBelowCap = usableSlots.some((s) => s.activeInflight < this.maxInflightPerSlot);
        if (anyBelowCap && remainingMs <= 0 && usableSlots.every((s) => s.cooldownUntil > Date.now())) {
          return this.pickFromPool(requestedModel, excludeKeys, conversationKey);
        }
        throw new GatewayError(
          "All upstream AWS Quick accounts are currently at concurrency capacity. Please retry in a few seconds.",
          429,
          "rate_limit_exceeded",
        );
      }

      // Wait until a compatible lease is released, a short cooldown expires, or the wait budget runs out.
      const soonestCooldownMs = usableSlots.reduce((min, s) => {
        if (s.cooldownUntil > now && s.activeInflight < this.maxInflightPerSlot) {
          return Math.min(min, s.cooldownUntil - now);
        }
        return min;
      }, remainingMs);
      const stepWaitMs = Math.max(25, Math.min(remainingMs, soonestCooldownMs));

      await new Promise<void>((resolve) => {
        let settled = false;
        const entry = {
          wake: () => finish(),
          canUse: (releasedSlot?: InternalKeySlot) => {
            if (!releasedSlot) return true;
            if (!releasedSlot.enabled || excludeKeys?.has(releasedSlot.rawKey)) return false;
            return !this.isSlotPoolExhausted(releasedSlot, targetPool);
          },
        };
        const finish = () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          opts?.signal?.removeEventListener("abort", onAbort);
          const idx = this.slotWaiters.indexOf(entry);
          if (idx >= 0) this.slotWaiters.splice(idx, 1);
          resolve();
        };
        const onAbort = () => finish();
        const timer = setTimeout(finish, stepWaitMs);
        // Do NOT unref: this timer is the only thing that guarantees the bounded soft-wait
        // settles. Unref'ing it lets the event loop drain while the caller still awaits the
        // promise (surfaces as "Promise resolution is still pending but the event loop has
        // already resolved" — node 22: release workflow tests 23/24/25 fail, no image built).
        if (hasWaited) {
          this.slotWaiters.unshift(entry);
        } else {
          this.slotWaiters.push(entry);
        }
        hasWaited = true;
        opts?.signal?.addEventListener("abort", onAbort, { once: true });
      });
    }
  }

  private pickFromPool(
    requestedModel: string,
    excludeKeys?: ReadonlySet<string>,
    conversationKey?: string
  ): KeyLease {
    const now = Date.now();
    const targetPool = classifyModelQuotaPool(requestedModel);

    // Clear expired cooldowns
    for (const s of this.slots) {
      if (s.cooldownUntil > 0 && s.cooldownUntil <= now) s.cooldownUntil = 0;
      if (s.connLimitCooldownUntil > 0 && s.connLimitCooldownUntil <= now) s.connLimitCooldownUntil = 0;
    }

    // Step 1: Check CPA-style Sticky Session Affinity first!
    // Elastic concurrency & brief conn-limit guard: if the sticky account is at maxInflightPerSlot
    // or in a brief 2.5s conn-limit backoff, borrow an idle account for this turn WITHOUT evicting
    // the sticky binding so subsequent turns still benefit from warm_incremental.
    if (this.sessionAffinityEnabled && conversationKey) {
      const stickyRawKey = this.affinityTable.lookup(conversationKey, this.sessionAffinityTtlMs);
      if (stickyRawKey && !excludeKeys?.has(stickyRawKey)) {
        const stickySlot = this.slots.find((s) => s.rawKey === stickyRawKey);
        const onlyBriefConnBackoff =
          stickySlot !== undefined &&
          stickySlot.enabled &&
          !this.isSlotPoolExhausted(stickySlot, targetPool) &&
          stickySlot.cooldownUntil > now &&
          stickySlot.connLimitCooldownUntil >= stickySlot.cooldownUntil;

        if (stickySlot && this.isSlotEligibleForPool(stickySlot, targetPool, now)) {
          if (stickySlot.activeInflight < this.maxInflightPerSlot) {
            return this.leaseSpecificKey(stickySlot.rawKey, true);
          }
          const spareCandidates = this.slots.filter(
            (s) =>
              s !== stickySlot &&
              !excludeKeys?.has(s.rawKey) &&
              this.isSlotEligibleForPool(s, targetPool, now) &&
              s.activeInflight < this.maxInflightPerSlot,
          );
          if (spareCandidates.length > 0) {
            const borrowed = this.pickBestCandidate(spareCandidates, targetPool);
            return this.leaseSpecificKey(borrowed.rawKey, false);
          }
          return this.leaseSpecificKey(stickySlot.rawKey, true);
        } else if (onlyBriefConnBackoff && stickySlot) {
          const spareCandidates = this.slots.filter(
            (s) =>
              s !== stickySlot &&
              !excludeKeys?.has(s.rawKey) &&
              this.isSlotEligibleForPool(s, targetPool, now) &&
              s.activeInflight < this.maxInflightPerSlot,
          );
          if (spareCandidates.length > 0) {
            const borrowed = this.pickBestCandidate(spareCandidates, targetPool);
            return this.leaseSpecificKey(borrowed.rawKey, false);
          }
          // Fall through without evicting sticky affinity
        } else {
          // Bound account is exhausted, in long rate-limit cooldown, or disabled -> break affinity cleanly!
          this.affinityTable.evictConversation(conversationKey);
        }
      }
    }

    const enabledSlots = this.slots.filter((s) => s.enabled && !excludeKeys?.has(s.rawKey));
    if (enabledSlots.length === 0) {
      throw new GatewayError("No enabled upstream AWS Quick credentials available.", 503, "no_enabled_keys");
    }

    let candidates = enabledSlots.filter((s) => s.cooldownUntil === 0);
    // All enabled accounts in transient 429 cooldown -> still run the exhaustion check below,
    // then pick the one whose cooldown expires soonest (strictly respecting maxInflightPerSlot).
    const allCoolingDown = candidates.length === 0;
    if (allCoolingDown) {
      candidates = [...enabledSlots].sort((a, b) => a.cooldownUntil - b.cooldownUntil);
    }

    // Filter out accounts whose target pool is exhausted without allowed fallback
    const nonExhausted = candidates.filter((s) => !this.isSlotPoolExhausted(s, targetPool));
    if (nonExhausted.length > 0) {
      candidates = nonExhausted;
    } else if (!candidates.some((s) => s.quota?.onDemandSpend.enabled)) {
      throw new GatewayError(
        `All enabled AWS Quick accounts have exhausted their '${targetPool}' quota.`,
        429,
        "quota_exhausted"
      );
    }

    if (allCoolingDown) {
      const belowCap = candidates.filter((s) => s.activeInflight < this.maxInflightPerSlot);
      if (belowCap.length === 0) {
        throw new GatewayError(
          "All upstream AWS Quick accounts are currently at concurrency capacity. Please retry in a few seconds.",
          429,
          "rate_limit_exceeded",
        );
      }
      return this.bindAndLease(belowCap[0]!, conversationKey);
    }

    const underCap = candidates.filter((s) => s.activeInflight < this.maxInflightPerSlot);
    if (underCap.length > 0) {
      candidates = underCap;
    }

    const picked = this.pickBestCandidate(candidates, targetPool);
    return this.bindAndLease(picked, conversationKey);
  }

  private pickBestCandidate(candidates: InternalKeySlot[], targetPool: "auto" | "api"): InternalKeySlot {
    if (this.lbStrategy === "round-robin") {
      return this.nextRoundRobin(candidates);
    }

    let pool = candidates;
    if (this.lbStrategy === "quota-aware") {
      const withIncluded = pool.filter((s) => {
        const rem = getRemainingPercentForPool(s.quota, targetPool);
        const flagged = targetPool === "auto" ? s.autoPoolExhausted : s.apiPoolExhausted;
        return !flagged && (rem === null || rem > 0);
      });
      if (withIncluded.length > 0) pool = withIncluded;
    }

    const n = this.slots.length;
    const startIdx = this.rrIndex;
    this.rrIndex = (this.rrIndex + 1) % Math.max(1, n);

    const sorted = [...pool].sort((a, b) => {
      if (a.activeInflight !== b.activeInflight) return a.activeInflight - b.activeInflight;
      if (this.lbStrategy === "quota-aware") {
        const remA = getRemainingPercentForPool(a.quota, targetPool);
        const remB = getRemainingPercentForPool(b.quota, targetPool);
        const bandA = remA !== null ? Math.floor(remA / 15) : 7;
        const bandB = remB !== null ? Math.floor(remB / 15) : 7;
        if (bandA !== bandB) return bandB - bandA;
      }
      const idxA = (this.slots.indexOf(a) - startIdx + n) % n;
      const idxB = (this.slots.indexOf(b) - startIdx + n) % n;
      return idxA - idxB;
    });

    return sorted[0]!;
  }

  private bindAndLease(slot: InternalKeySlot, conversationKey?: string): KeyLease {
    if (this.sessionAffinityEnabled && conversationKey) {
      this.affinityTable.bind({
        conversationKey,
        rawKey: slot.rawKey,
        slotId: slot.slotId,
        maskedKey: slot.maskedKey,
        ttlMs: this.sessionAffinityTtlMs
      });
    }
    return this.leaseSpecificKey(slot.rawKey, false);
  }

  private nextRoundRobin(candidates: InternalKeySlot[]): InternalKeySlot {
    const n = this.slots.length;
    for (let offset = 0; offset < n; offset += 1) {
      const slot = this.slots[(this.rrIndex + offset) % n]!;
      if (candidates.includes(slot)) {
        this.rrIndex = (this.rrIndex + offset + 1) % n;
        return slot;
      }
    }
    return candidates[0]!;
  }

  /**
   * Brief non-escalating backoff for AWS Quick's per-account 5-WS concurrency ceiling
   * (`LimitExceededException: Too many active connections. Maximum allowed: 5`).
   * Does NOT escalate exponential cooldown (60s-300s) and does NOT evict sticky affinity.
   */
  reportConnLimit(rawKey: string, backoffMs = DEFAULT_CONN_LIMIT_COOLDOWN_MS): void {
    const slot = this.slots.find((s) => s.rawKey === rawKey);
    if (!slot) return;
    slot.rateLimits += 1;
    const until = Date.now() + Math.max(500, backoffMs);
    if (until > slot.connLimitCooldownUntil) slot.connLimitCooldownUntil = until;
    if (until > slot.cooldownUntil) slot.cooldownUntil = until;
  }

  /**
   * CPA-style exponential backoff cooldown for transient 429 burst errors (30s -> 60s -> 120s -> max 300s).
   */
  reportRateLimit(rawKey: string): void {
    const slot = this.slots.find((s) => s.rawKey === rawKey);
    if (!slot) return;
    slot.rateLimits += 1;
    slot.consecutiveRateLimits += 1;
    const multiplier = Math.min(10, 2 ** (slot.consecutiveRateLimits - 1));
    const backoffMs = Math.min(300_000, this.baseCooldownMs * multiplier);
    slot.cooldownUntil = Date.now() + backoffMs;
    this.affinityTable.evictAllForKey(rawKey);
  }

  /**
   * Circuit breaker when an account runs out of money/quota mid-flight!
   * Evicts sticky sessions from Account A so they seamlessly rebind to Account B,
   * marks the affected pool exhausted, and auto-disables Account A if configured!
   */
  reportQuotaExhausted(rawKey: string, _requestedModel: string, reasonDetail?: string): void {
    const slot = this.slots.find((s) => s.rawKey === rawKey);
    if (!slot) return;
    slot.quotaExhaustedHits += 1;
    this.affinityTable.evictAllForKey(rawKey);

    // On AWS Quick, hitting the 5h burst window or monthly 10h pool blocks ALL models on the account.
    // Mark both pools exhausted and auto-disable immediately regardless of stale cached quota telemetry.
    slot.autoPoolExhausted = true;
    slot.apiPoolExhausted = true;

    if (this.autoDisableExhaustedKeys) {
      slot.enabled = false;
      slot.autoDisabledKind = "quota";
      slot.autoDisabledReason = reasonDetail
        ? `Auto-disabled (quota exhausted): ${redactSecrets(reasonDetail).slice(0, 60)}`
        : "Auto-disabled: quota exhausted";
      this.persist();
    }
  }

  reportAuthFailure(rawKey: string, reasonDetail?: string): void {
    const slot = this.slots.find((s) => s.rawKey === rawKey);
    if (!slot) return;
    slot.authErrors += 1;
    this.affinityTable.evictAllForKey(rawKey);

    if (this.autoDisableExhaustedKeys) {
      slot.enabled = false;
      slot.autoDisabledKind = "auth";
      slot.autoDisabledReason = reasonDetail
        ? `Auto-disabled (auth failed): ${redactSecrets(reasonDetail).slice(0, 60)}`
        : "Auto-disabled: authentication failed (401 Unauthorized)";
      this.persist();
    } else {
      slot.cooldownUntil = Date.now() + this.baseCooldownMs * 10;
    }
  }

  /**
   * Update live quota telemetry from `/auth/usage-summary` and proactively trip/reset exhaustion flags!
   */
  updateSlotQuotaCache(
    rawKey: string,
    identity?: KeyIdentitySummary,
    quota?: QuickPlanQuotaView,
    bot?: BotQuotaView,
    extra?: { cloudSessionCount?: number | null; tokenRemainingSec?: number | null; syncError?: string | null },
  ): void {
    const slot = this.slots.find((s) => s.rawKey === rawKey);
    if (!slot) return;
    if (extra?.syncError !== undefined) {
      slot.lastSyncError = extra.syncError ? extra.syncError.slice(0, 220) : undefined;
    }
    if (identity) {
      slot.identity = identity;
      const email = identity.userEmail && identity.userEmail.includes("@") ? identity.userEmail : undefined;
      const dname = identity.displayName || undefined;
      const prev = this.savedIdentities[slot.slotId];
      if ((email || dname) && (prev?.userEmail !== email || prev?.displayName !== dname)) {
        this.savedIdentities[slot.slotId] = {
          ...(email ? { userEmail: email } : prev?.userEmail ? { userEmail: prev.userEmail } : {}),
          ...(dname ? { displayName: dname } : prev?.displayName ? { displayName: prev.displayName } : {}),
        };
        this.persistSavedIdentities();
      }
    }
    if (extra?.cloudSessionCount !== undefined) slot.cloudSessionCount = extra.cloudSessionCount;
    if (extra?.tokenRemainingSec !== undefined) slot.tokenRemainingSec = extra.tokenRemainingSec;
    if (bot) slot.bot = bot;
    if (!quota) return;

    slot.quota = quota;
    slot.quotaUpdatedAt = new Date().toISOString();

    const now = Date.now();
    const prevResetMs = slot.autoResetAtMs;
    const autoRem = quota.sessionPool.remainingPercent;
    const apiRem = quota.premiumApiPool.remainingPercent;

    slot.autoPoolExhausted = autoRem !== null && autoRem <= 0;
    slot.apiPoolExhausted = apiRem !== null && apiRem <= 0;
    const exhausted = slot.autoPoolExhausted || slot.apiPoolExhausted;

    const billingEndMs = quota.billingCycleEnd ? Date.parse(quota.billingCycleEnd) : Number.NaN;
    const rawSessionResumeMs = quota.sessionPool.resumeAt
      ? Date.parse(quota.sessionPool.resumeAt)
      : typeof quota.sessionPool.resumeInMinutes === "number" && quota.sessionPool.resumeInMinutes > 0
        ? now + Math.ceil(quota.sessionPool.resumeInMinutes) * 60_000
        : Number.NaN;

    // If ONLY the 5h session burst pool is exhausted (monthly 10h pool still has quota),
    // schedule auto-recovery using AWS Quick's exact `resume_in_minutes` instead of waiting for next month!
    if (slot.autoPoolExhausted && !slot.apiPoolExhausted && Number.isFinite(rawSessionResumeMs) && rawSessionResumeMs > now) {
      slot.autoResetAtMs = rawSessionResumeMs;
    } else if (Number.isFinite(billingEndMs)) {
      slot.autoResetAtMs = billingEndMs;
    }

    // Proactive auto-disable if either Session burst pool or Monthly 10h pool hits 0%.
    if (this.autoDisableExhaustedKeys && slot.enabled && exhausted) {
      slot.enabled = false;
      slot.autoDisabledKind = "quota";
      slot.autoDisabledReason = slot.apiPoolExhausted
        ? "Auto-disabled: Monthly 10h pool reached 0%"
        : "Auto-disabled: Session burst pool reached 0%";
      this.affinityTable.evictAllForKey(rawKey);
      this.persist();
      return;
    }

    // Recovery: a quota-tripped key that fresh telemetry shows has quota again is re-enabled.
    if (!slot.enabled && slot.autoDisabledKind === "quota") {
      if (!exhausted) {
        slot.enabled = true;
        slot.autoDisabledReason = undefined;
        slot.autoDisabledKind = undefined;
        slot.autoResetAtMs = undefined;
        slot.cooldownUntil = 0;
        slot.connLimitCooldownUntil = 0;
        slot.consecutiveRateLimits = 0;
        this.persist();
        this.notifySlotAvailable(slot, this.maxInflightPerSlot);
        return;
      }
      if (slot.autoResetAtMs !== prevResetMs) this.persist();
    }
  }

  /** Quota-tripped keys that should be probed for recovery (disabled by the gateway, not by a person). */
  recoveryProbeKeys(): string[] {
    return this.slots.filter((s) => !s.enabled && s.autoDisabledKind === "quota").map((s) => s.rawKey);
  }

  /** Clear an automatic trip so the key is used again; the next request or sync re-trips it if still bad. */
  recheckSlot(slotId: string): void {
    const slot = this.slots.find((s) => s.slotId === slotId);
    if (!slot) throw new GatewayError(`Key slot '${slotId}' not found.`, 404, "not_found");
    if (!slot.enabled && slot.autoDisabledKind) {
      slot.enabled = true;
      slot.autoDisabledReason = undefined;
      slot.autoDisabledKind = undefined;
      slot.autoResetAtMs = undefined;
      slot.apiPoolExhausted = false;
      slot.autoPoolExhausted = false;
      slot.cooldownUntil = 0;
      slot.connLimitCooldownUntil = 0;
      slot.consecutiveRateLimits = 0;
      this.persist();
      this.notifySlotAvailable(slot, this.maxInflightPerSlot);
    }
  }

  addKey(rawKey: string, enabled = true, label?: string, proxyUrl?: string, chatAgentId?: string): KeySlotStatus {
    let validProxy: string | undefined;
    try {
      validProxy = validateProxyUrl(proxyUrl);
    } catch (err) {
      throw new GatewayError(err instanceof Error ? err.message : "Invalid proxy URL.", 400, "invalid_proxy_url");
    }
    const validChatAgentId = validateChatAgentId(chatAgentId);
    let normalized = rawKey.trim();
    const webCred = parseWebCurlOrCredential(normalized);
    if (webCred) {
      normalized = serializeWebCredential(webCred);
      // Manual renewal: if a web credential for the same AWS account already exists, refresh it in place.
      const prefix = `web:${webCred.accountId}|`;
      const existing = this.slots.find((s) => s.rawKey.startsWith(prefix));
      if (existing) {
        existing.rawKey = normalized;
        existing.maskedKey = maskSecretKey(normalized);
        existing.enabled = enabled;
        existing.autoDisabledKind = undefined;
        existing.autoDisabledReason = undefined;
        existing.cooldownUntil = 0;
        existing.connLimitCooldownUntil = 0;
        if (label?.trim()) existing.label = label.trim();
        if (proxyUrl !== undefined) existing.proxyUrl = validProxy;
        if (chatAgentId !== undefined) existing.chatAgentId = validChatAgentId;
        this.persist();
        if (enabled) this.notifySlotAvailable(existing, this.maxInflightPerSlot);
        return this.toSlotStatus(existing, this.affinityTable.countBySlot());
      }
    } else if (!normalized || normalized.length < 4 || /[\r\n]/.test(normalized)) {
      throw new GatewayError(
        "Invalid AWS Quick credential (use `local-outpost`, `id_token`, or pasted `Copy as cURL` from quick.aws.com).",
        400,
        "invalid_api_key",
      );
    }
    const autoWebLabel = webCred ? (webCred.email || `AWS #${webCred.accountId.slice(-4)}`) : undefined;
    const slot = this.upsertInternal(normalized, enabled, label || autoWebLabel);
    if (proxyUrl !== undefined) slot.proxyUrl = validProxy;
    if (chatAgentId !== undefined) slot.chatAgentId = validChatAgentId;
    this.persist();
    if (enabled) this.notifySlotAvailable(slot, this.maxInflightPerSlot);
    return this.toSlotStatus(slot, this.affinityTable.countBySlot());
  }

  updateSlotMeta(
    slotId: string,
    patch: { enabled?: boolean; label?: string; proxyUrl?: string; chatAgentId?: string; clearCooldown?: boolean }
  ): KeySlotStatus {
    const slot = this.slots.find((s) => s.slotId === slotId);
    if (!slot) throw new GatewayError(`Key slot '${slotId}' not found.`, 404, "not_found");

    if (patch.clearCooldown) {
      slot.cooldownUntil = 0;
      slot.connLimitCooldownUntil = 0;
      slot.consecutiveRateLimits = 0;
    }
    if (patch.label !== undefined) {
      slot.label = patch.label.trim() || undefined;
    }
    if (patch.proxyUrl !== undefined) {
      try {
        slot.proxyUrl = validateProxyUrl(patch.proxyUrl);
      } catch (err) {
        throw new GatewayError(err instanceof Error ? err.message : "Invalid proxy URL.", 400, "invalid_proxy_url");
      }
    }
    if (patch.chatAgentId !== undefined) {
      slot.chatAgentId = validateChatAgentId(patch.chatAgentId);
    }
    if (typeof patch.enabled === "boolean") {
      slot.enabled = patch.enabled;
      if (patch.enabled) {
        slot.cooldownUntil = 0;
        slot.connLimitCooldownUntil = 0;
        slot.consecutiveRateLimits = 0;
        slot.apiPoolExhausted = false;
        slot.autoPoolExhausted = false;
        slot.autoDisabledReason = undefined;
        slot.autoDisabledKind = undefined;
      } else {
        slot.autoDisabledReason = undefined;
        slot.autoDisabledKind = undefined;
        this.affinityTable.evictAllForKey(slot.rawKey);
      }
    }
    this.persist();
    if (slot.enabled && (patch.enabled === true || patch.clearCooldown)) {
      this.notifySlotAvailable(slot, this.maxInflightPerSlot);
    }
    return this.toSlotStatus(slot, this.affinityTable.countBySlot());
  }

  removeKey(slotId: string): void {
    const idx = this.slots.findIndex((s) => s.slotId === slotId);
    if (idx < 0) throw new GatewayError(`Key slot '${slotId}' not found.`, 404, "not_found");
    const [removed] = this.slots.splice(idx, 1);
    if (removed) {
      this.affinityTable.evictAllForKey(removed.rawKey);
      evictQuotaCachesForKey(removed.rawKey);
    }
    this.persist();
  }

  affinitySnapshot(limit = 50): AffinityBindingView[] {
    return this.affinityTable.snapshot(limit);
  }

  clearAffinity(): void {
    this.affinityTable.clearAll();
  }

  private toSlotStatus(slot: InternalKeySlot, stickyCounts: Map<string, number>): KeySlotStatus {
    const rem = Math.max(0, slot.cooldownUntil - Date.now());
    return {
      slotId: slot.slotId,
      ...(slot.label ? { label: slot.label } : {}),
      authType: slot.authType,
      addedAt: slot.addedAt,
      maskedKey: slot.maskedKey,
      ...(slot.proxyUrl ? { maskedProxy: maskProxyUrl(slot.proxyUrl) } : {}),
      ...(slot.chatAgentId ? { chatAgentId: slot.chatAgentId } : {}),
      enabled: slot.enabled,
      healthy: slot.enabled && rem === 0 && !slot.autoPoolExhausted && !slot.apiPoolExhausted,
      ...(slot.autoDisabledReason ? { autoDisabledReason: slot.autoDisabledReason } : {}),
      ...(slot.autoDisabledKind && !slot.enabled ? { autoDisabledKind: slot.autoDisabledKind } : {}),
      ...(slot.autoDisabledKind === "quota" && !slot.enabled && slot.autoResetAtMs ? { autoRecoverAt: new Date(slot.autoResetAtMs).toISOString() } : {}),
      apiPoolExhausted: slot.apiPoolExhausted,
      autoPoolExhausted: slot.autoPoolExhausted,
      activeInflight: slot.activeInflight,
      stickySessions: stickyCounts.get(slot.slotId) ?? 0,
      cooldownRemainingMs: rem,
      totalSelected: slot.selected,
      affinityHits: slot.affinityHits,
      rateLimitHits: slot.rateLimits,
      quotaExhaustedHits: slot.quotaExhaustedHits,
      authErrors: slot.authErrors,
      ...(slot.identity ? { identity: slot.identity } : {}),
      ...(slot.quota ? { quota: slot.quota } : {}),
      ...(slot.bot ? { bot: slot.bot } : {}),
      ...(slot.cloudSessionCount !== undefined ? { cloudSessionCount: slot.cloudSessionCount } : {}),
      ...(slot.tokenRemainingSec !== undefined ? { tokenRemainingSec: slot.tokenRemainingSec } : {}),
      ...(slot.lastSyncError ? { lastSyncError: slot.lastSyncError } : {}),
      ...(slot.quotaUpdatedAt ? { quotaUpdatedAt: slot.quotaUpdatedAt } : {})
    };
  }

  statusSnapshot(): KeySlotStatus[] {
    this.reviveCycleResetAccounts();
    const stickyCounts = this.affinityTable.countBySlot();
    return this.slots.map((s) => this.toSlotStatus(s, stickyCounts));
  }
}
