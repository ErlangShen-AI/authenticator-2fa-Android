import { base64ToBytes, bytesToBase64, decodeBase32, encodeBase32 } from './base32';
import { normalizeImportedAccounts } from './otp';
import type { AuthenticatorAccount } from './types';

export const SYNC_PREFIX = 'authenticator-sync-v1:';
export const MAX_SYNC_ITEM_BYTES = 8192;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const INVALID_DATA = 'Browser Sync data is not valid.';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export interface BrowserSyncRecord {
  id: string;
  revision: number;
  deviceId: string;
  account: AuthenticatorAccount | null;
}

/** Stored only inside the password-protected local vault, never in storage.sync. */
export interface BrowserSyncState {
  recoveryKey: string;
  deviceId: string;
  records: Record<string, BrowserSyncRecord>;
}

export interface BrowserSyncEnvelope {
  version: 1;
  iv: string;
  data: string;
}

export interface BrowserSyncItem {
  storageKey: string;
  value: BrowserSyncEnvelope;
}

export function generateSyncRecoveryKey(): string {
  return formatRecoveryKey(encodeBase32(crypto.getRandomValues(new Uint8Array(32))));
}

export function parseSyncRecoveryKey(input: string): string {
  const normalized = input.replace(/[\s-]/g, '').toUpperCase();
  const encoded = normalized.slice(5);
  if (
    !normalized.startsWith('A2FA1') ||
    !/^[A-Z2-7]{52}$/.test(encoded) ||
    encodeBase32(decodeBase32(encoded)) !== encoded
  ) {
    throw new Error('Browser Sync recovery key is not valid.');
  }
  return formatRecoveryKey(encoded);
}

export async function getSyncNamespace(recoveryKey: string): Promise<string> {
  return hash(`${SYNC_PREFIX}${parseSyncRecoveryKey(recoveryKey)}`);
}

export async function getSyncMarkerKey(recoveryKey: string): Promise<string> {
  return `${SYNC_PREFIX}${await getSyncNamespace(recoveryKey)}:marker`;
}

export async function createSyncMarker(recoveryKey: string): Promise<BrowserSyncItem> {
  const storageKey = await getSyncMarkerKey(recoveryKey);
  return encryptValue(recoveryKey, storageKey, { version: 1, kind: 'browser-sync' });
}

export async function validateSyncMarker(recoveryKey: string, value: unknown): Promise<void> {
  const plaintext = await decryptValue(recoveryKey, await getSyncMarkerKey(recoveryKey), value);
  if (!isObject(plaintext) || plaintext.version !== 1 || plaintext.kind !== 'browser-sync') {
    throw new Error(INVALID_DATA);
  }
}

export async function encryptSyncRecord(
  recoveryKey: string,
  record: BrowserSyncRecord
): Promise<BrowserSyncItem> {
  const normalized = normalizeSyncRecord(record);
  return encryptValue(recoveryKey, await getRecordKey(recoveryKey, normalized), normalized);
}

export async function decryptSyncRecord(
  recoveryKey: string,
  storageKey: string,
  value: unknown
): Promise<BrowserSyncRecord> {
  const namespace = `${SYNC_PREFIX}${await getSyncNamespace(recoveryKey)}:`;
  if (!storageKey.startsWith(namespace) || storageKey.length > 160) {
    throw new Error(INVALID_DATA);
  }
  const record = normalizeSyncRecord(await decryptValue(recoveryKey, storageKey, value));
  if (storageKey !== await getRecordKey(recoveryKey, record)) {
    throw new Error(INVALID_DATA);
  }
  return record;
}

/** Deletion is permanent for an account ID; adding the account again creates a new ID. */
export function mergeSyncRecords(records: readonly BrowserSyncRecord[]): BrowserSyncRecord[] {
  const groups = new Map<string, BrowserSyncRecord[]>();
  for (const value of records) {
    const record = normalizeSyncRecord(value);
    const group = groups.get(record.id) ?? [];
    group.push(record);
    groups.set(record.id, group);
  }

  return Array.from(groups.values(), (group) => {
    const deleted = group.filter((record) => record.account === null);
    const candidates = deleted.length ? deleted : group;
    const winner = candidates.reduce((left, right) => compareRecords(left, right) >= 0 ? left : right);
    if (winner.account?.type !== 'hotp') return winner;

    const account = winner.account;
    const counter = Math.max(...group.map((record) => {
      const other = record.account;
      return other?.type === 'hotp' && other.secret === account.secret && other.algorithm === account.algorithm
        ? other.counter : account.counter;
    }));
    return { ...winner, account: { ...account, counter } };
  }).sort((left, right) => compareText(left.id, right.id));
}

/** Joining keeps existing remote identities, while retaining distinct local accounts. */
export function alignSyncAccounts(
  localAccounts: readonly AuthenticatorAccount[],
  remoteRecords: readonly BrowserSyncRecord[]
): AuthenticatorAccount[] {
  const remote = mergeSyncRecords(remoteRecords);
  const recordsById = new Map(remote.map((record) => [record.id, record]));
  const accounts = remote.flatMap((record) => record.account ? [record.account] : []);
  const byFingerprint = new Map(accounts.map((account) => [accountFingerprint(account), account]));
  const byId = new Map(accounts.map((account) => [account.id, account]));
  for (const local of normalizeImportedAccounts(localAccounts)) {
    if (recordsById.get(local.id)?.account === null) continue;
    const existing = byId.get(local.id) ?? byFingerprint.get(accountFingerprint(local));
    if (existing) {
      if (local.sortOrder !== undefined) existing.sortOrder = local.sortOrder;
      if (existing.type === 'hotp' && local.type === 'hotp' && existing.secret === local.secret && existing.algorithm === local.algorithm) {
        existing.counter = Math.max(existing.counter, local.counter);
      }
      continue;
    }
    accounts.push(local);
    byId.set(local.id, local);
    byFingerprint.set(accountFingerprint(local), local);
  }
  return accounts;
}

/**
 * Diff against the last applied local baseline before merging incoming records. An
 * account absent on a device that has never seen it must not become a deletion.
 * Returning every local winner makes failed uploads safely retryable.
 */
export function reconcileSyncAccounts(
  state: BrowserSyncState,
  currentAccounts: readonly AuthenticatorAccount[],
  remoteRecords: readonly BrowserSyncRecord[]
): { state: BrowserSyncState; accounts: AuthenticatorAccount[]; writes: BrowserSyncRecord[] } {
  if (!UUID.test(state.deviceId)) throw new Error(INVALID_DATA);
  const recoveryKey = parseSyncRecoveryKey(state.recoveryKey);
  const baseline = Object.values(state.records).map(normalizeSyncRecord);
  const current = normalizeImportedAccounts(currentAccounts);
  const currentById = new Map(current.map((account) => [account.id, account]));
  if (currentById.size !== current.length) throw new Error(INVALID_DATA);
  const previousById = new Map(baseline.map((record) => [record.id, record]));
  let revision = Math.max(0, ...baseline.map((record) => record.revision));
  const nextRevision = () => {
    if (revision >= Number.MAX_SAFE_INTEGER) throw new Error(INVALID_DATA);
    return ++revision;
  };
  const changes: BrowserSyncRecord[] = [];

  for (const account of current) {
    const previous = previousById.get(account.id);
    const syncedAccount = withoutLocalOrder(account);
    if (!previous || JSON.stringify(previous.account) !== JSON.stringify(syncedAccount)) {
      changes.push({ id: account.id, revision: nextRevision(), deviceId: state.deviceId, account: syncedAccount });
    }
  }
  for (const previous of baseline) {
    if (previous.account && !currentById.has(previous.id)) {
      changes.push({ id: previous.id, revision: nextRevision(), deviceId: state.deviceId, account: null });
    }
  }

  const candidates = [...baseline, ...changes, ...remoteRecords.map(normalizeSyncRecord)];
  revision = Math.max(revision, ...candidates.map((record) => record.revision));
  const candidateValues = new Set(candidates.map((record) => JSON.stringify(record)));
  const merged = mergeSyncRecords(candidates).map((record) => {
    // A counter merged from an older record needs its own revision so it is
    // persisted in this device's slot without rewriting another device's slot.
    if (!candidateValues.has(JSON.stringify(record))) {
      return { ...record, revision: nextRevision(), deviceId: state.deviceId };
    }
    return record;
  });
  const surviving = new Map(merged.flatMap((record) => record.account ? [[record.id, record.account] as const] : []));
  const accounts: AuthenticatorAccount[] = [];
  let nextOrder = current.reduce((maximum, account, index) => Math.max(maximum, account.sortOrder ?? index), -1) + 1;
  for (const account of current) {
    const survivor = surviving.get(account.id);
    if (survivor) accounts.push(account.sortOrder === undefined ? survivor : { ...survivor, sortOrder: account.sortOrder });
    surviving.delete(account.id);
  }
  accounts.push(...Array.from(surviving.values(), (account) => ({ ...account, sortOrder: nextOrder++ })));

  return {
    state: { recoveryKey, deviceId: state.deviceId, records: Object.fromEntries(merged.map((record) => [record.id, record])) },
    accounts,
    writes: merged.filter((record) => record.deviceId === state.deviceId)
  };
}

function normalizeSyncRecord(value: unknown): BrowserSyncRecord {
  if (
    !isObject(value) || typeof value.id !== 'string' || !value.id.trim() || value.id.length > 512 ||
    typeof value.deviceId !== 'string' || !UUID.test(value.deviceId) ||
    typeof value.revision !== 'number' || !Number.isSafeInteger(value.revision) || value.revision < 1
  ) throw new Error(INVALID_DATA);

  const account = value.account === null ? null : withoutLocalOrder(normalizeImportedAccounts([value.account])[0]);
  if (account && (account.id !== value.id || !Number.isFinite(Date.parse(account.createdAt)) || !Number.isFinite(Date.parse(account.updatedAt)))) {
    throw new Error(INVALID_DATA);
  }
  return { id: value.id, revision: value.revision, deviceId: value.deviceId, account };
}

async function getRecordKey(recoveryKey: string, record: BrowserSyncRecord): Promise<string> {
  const namespace = await getSyncNamespace(recoveryKey);
  // Imported IDs can contain personal data. Include the secret recovery key in
  // the opaque identifier so public storage metadata cannot be dictionary-tested.
  const accountToken = await hash(`${parseSyncRecoveryKey(recoveryKey)}:account:${record.id}`);
  return `${SYNC_PREFIX}${namespace}:${record.deviceId}:${accountToken}`;
}

async function encryptValue(recoveryKey: string, storageKey: string, value: unknown): Promise<BrowserSyncItem> {
  const plaintext = encoder.encode(JSON.stringify(value));
  if (plaintext.length > MAX_SYNC_ITEM_BYTES) throw new Error('Browser Sync account exceeds the storage limit.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(storageKey) },
    await importSyncKey(recoveryKey),
    plaintext
  );
  const envelope: BrowserSyncEnvelope = { version: 1, iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ciphertext)) };
  if (encoder.encode(JSON.stringify({ [storageKey]: envelope })).length > MAX_SYNC_ITEM_BYTES) {
    throw new Error('Browser Sync account exceeds the storage limit.');
  }
  return { storageKey, value: envelope };
}

async function decryptValue(recoveryKey: string, storageKey: string, value: unknown): Promise<unknown> {
  if (
    !isObject(value) || value.version !== 1 || typeof value.iv !== 'string' || value.iv.length !== 16 ||
    typeof value.data !== 'string' || value.data.length < 24 || value.data.length > MAX_SYNC_ITEM_BYTES ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value.data) || !/^[A-Za-z0-9+/]{16}$/.test(value.iv)
  ) throw new Error(INVALID_DATA);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toBuffer(base64ToBytes(value.iv)), additionalData: encoder.encode(storageKey) },
    await importSyncKey(recoveryKey),
    toBuffer(base64ToBytes(value.data))
  );
  return JSON.parse(decoder.decode(plaintext));
}

async function importSyncKey(recoveryKey: string): Promise<CryptoKey> {
  const encoded = parseSyncRecoveryKey(recoveryKey).replace(/-/g, '').slice(5);
  return crypto.subtle.importKey('raw', toBuffer(decodeBase32(encoded)), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function hash(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text)));
  return Array.from(digest.subarray(0, 16), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function formatRecoveryKey(encoded: string): string {
  return `A2FA1-${encoded.match(/.{4}/g)!.join('-')}`;
}

function toBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function compareRecords(left: BrowserSyncRecord, right: BrowserSyncRecord): number {
  return left.revision - right.revision || compareText(left.deviceId, right.deviceId) ||
    compareText(JSON.stringify(left.account), JSON.stringify(right.account));
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function accountFingerprint(account: AuthenticatorAccount): string {
  return JSON.stringify([
    account.type, account.issuer.toLowerCase(), account.label.toLowerCase(), account.secret,
    account.algorithm, account.digits, account.period
  ]);
}

function withoutLocalOrder(account: AuthenticatorAccount): AuthenticatorAccount {
  const syncedAccount = { ...account };
  delete syncedAccount.sortOrder;
  return syncedAccount;
}
