import { base64ToBytes, bytesToBase64, decodeBase32, encodeBase32 } from './base32';
import { accountFingerprint, normalizeImportedAccounts } from './otp';
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
  /** Earlier identities of the same account, retained through edits and deletion. */
  mergedIds?: string[];
  /** An explicit restore starts a new identity, protected from older deletions. */
  restorationId?: string;
  /** Encrypted fingerprints of source IDs and credentials, retained on deletion. */
  origins?: string[];
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
  const normalized = await withSyncOrigin(record);
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

/** Deletion is permanent for an identity and its known duplicates. */
export function mergeSyncRecords(records: readonly BrowserSyncRecord[]): BrowserSyncRecord[] {
  const normalized = records.map(normalizeSyncRecord);
  const parents = new Map<string, string>();
  const identity = (record: BrowserSyncRecord, id: string, kind = 'id') => JSON.stringify([record.restorationId ?? '', kind, id]);
  const root = (id: string): string => {
    const path: string[] = [];
    while (parents.has(id)) {
      path.push(id);
      id = parents.get(id)!;
    }
    for (const child of path) parents.set(child, id);
    return id;
  };
  for (const record of normalized) {
    const links = [
      ...(record.mergedIds ?? []).map((id) => identity(record, id)),
      ...(record.origins ?? []).map((origin) => identity(record, origin, 'origin'))
    ];
    for (const link of links) {
      const left = root(identity(record, record.id));
      const right = root(link);
      if (left !== right) parents.set(right, left);
    }
  }

  const groups = new Map<string, BrowserSyncRecord[]>();
  for (const record of normalized) {
    const id = root(identity(record, record.id));
    const group = groups.get(id) ?? [];
    group.push(record);
    groups.set(id, group);
  }

  const identities = Array.from(groups.values(), mergeRecordGroup);
  const restorations = identities.filter((record) => record.restorationId);
  const independent: BrowserSyncRecord[] = [];
  for (const record of identities.filter((record) => !record.restorationId)) {
    let superseded = false;
    for (let index = 0; index < restorations.length; index++) {
      if (recordsOverlap(record, restorations[index])) {
        // Keep late alias links even when their old identity is already deleted.
        restorations[index] = mergeRecordGroup([restorations[index], record]);
        superseded = true;
      }
    }
    if (!superseded) independent.push(record);
  }

  // Deleted identities cannot fingerprint-match a new restoration.
  const deleted: BrowserSyncRecord[] = [];
  const fingerprints = new Map<string, BrowserSyncRecord[]>();
  for (const record of [...restorations, ...independent]) {
    if (!record.account) {
      deleted.push(record);
      continue;
    }
    const fingerprint = accountFingerprint(record.account);
    const duplicates = fingerprints.get(fingerprint) ?? [];
    duplicates.push(record);
    fingerprints.set(fingerprint, duplicates);
  }
  const live = Array.from(fingerprints.values()).flatMap((group) => {
    const restored = group.filter((record) => record.restorationId).sort((left, right) => compareText(left.id, right.id));
    if (restored.length === 0) return [mergeRecordGroup(group)];
    const copies = group.filter((record) => !record.restorationId);
    // Independent explicit restores stay separate; ordinary joining copies
    // adopt a restored identity without transferring old deletions into it.
    return restored.map((record, index) => index === 0 ? mergeRecordGroup([record, ...copies]) : record);
  });
  return [...deleted, ...live]
    .sort((left, right) => compareText(left.id, right.id));
}

function mergeRecordGroup(group: BrowserSyncRecord[]): BrowserSyncRecord {
  const restored = group.filter((record) => record.restorationId);
  const generation = restored.length ? restored : group;
  const deleted = generation.filter((record) => record.account === null);
  const candidates = deleted.length ? deleted : generation;
  const winner = candidates.reduce((left, right) => compareRecords(left, right) >= 0 ? left : right);
  const ids = Array.from(new Set(group.flatMap(recordIds))).sort(compareText);
  const id = winner.restorationId ?? ids[0];
  const mergedIds = ids.filter((value) => value !== id);
  const origins = Array.from(new Set(group.flatMap((record) => record.origins ?? []))).sort(compareText);
  let account = winner.account && { ...winner.account, id };
  if (account?.type === 'hotp') {
    const hotp = account;
    const counter = Math.max(...group.map((record) => {
      const other = record.account;
      return other?.type === 'hotp' && other.secret === hotp.secret && other.algorithm === hotp.algorithm
        ? other.counter : hotp.counter;
    }));
    account = { ...account, counter };
  }
  return {
    id, revision: winner.revision, deviceId: winner.deviceId, account,
    ...(mergedIds.length ? { mergedIds } : {}),
    ...(winner.restorationId ? { restorationId: winner.restorationId } : {}),
    ...(origins.length ? { origins } : {})
  };
}

/** Preserve independent credentials and retain the identities of joining copies. */
export async function joinSyncAccounts(
  state: BrowserSyncState,
  localAccounts: readonly AuthenticatorAccount[],
  newGroup = false
) {
  const remote = mergeSyncRecords(await withSyncOrigins(Object.values(state.records)));
  const recordsById = indexSyncIdentities(remote);
  const accounts = remote.flatMap((record) => record.account ? [{ ...record.account }] : []);
  const accountsById = new Map(accounts.map((account) => [account.id, account]));
  const byFingerprint = new Map(accounts.map((account) => [accountFingerprint(account), account]));
  const records = Object.fromEntries(remote.map((record) => [record.id, record]));
  let revision = Math.max(0, ...remote.map((record) => record.revision));
  for (const local of normalizeImportedAccounts(localAccounts)) {
    const origin = await accountOrigin(local);
    const previous = recordsById.get(local.id);
    if (previous?.account === null && previous.origins?.includes(origin)) continue;
    const sameId = accountsById.get(recordsById.get(local.id)?.id ?? '');
    const known = sameId && sameCredentials(sameId, local);
    const existing = known ? sameId : byFingerprint.get(accountFingerprint(local));
    if (existing) {
      if (local.sortOrder !== undefined) existing.sortOrder = local.sortOrder;
      if (existing.type === 'hotp' && local.type === 'hotp') {
        existing.counter = Math.max(existing.counter, local.counter);
      }
      if (known) continue;
    }
    // Delivery may be incomplete. An unproven source ID must never claim a
    // remote identity. Its credential-scoped origin still recognizes late copies.
    const joining = { ...(existing ?? local), id: newGroup ? local.id : crypto.randomUUID() };
    if (!Number.isSafeInteger(++revision)) throw new Error(INVALID_DATA);
    records[joining.id] = await withSyncOrigin({
      id: joining.id, revision, deviceId: state.deviceId, account: joining,
      origins: [origin, await accountOrigin(joining)]
    });
    accounts.push(joining);
    if (!existing) byFingerprint.set(accountFingerprint(joining), joining);
  }
  return reconcileSyncAccounts({ ...state, records }, accounts, []);
}

/**
 * Diff against the last applied local baseline before merging incoming records. An
 * account absent on a device that has never seen it must not become a deletion.
 * Returning every local winner makes failed uploads safely retryable.
 */
export function reconcileSyncAccounts(
  state: BrowserSyncState,
  currentAccounts: readonly AuthenticatorAccount[],
  remoteRecords: readonly BrowserSyncRecord[],
  restoredIds: readonly string[] = []
): { state: BrowserSyncState; accounts: AuthenticatorAccount[]; writes: BrowserSyncRecord[] } {
  if (!UUID.test(state.deviceId)) throw new Error(INVALID_DATA);
  const recoveryKey = parseSyncRecoveryKey(state.recoveryKey);
  const baseline = Object.values(state.records).map(normalizeSyncRecord);
  const previousById = new Map(baseline.map((record) => [record.id, record]));
  const restorations = new Set(restoredIds);
  const normalized = normalizeImportedAccounts(currentAccounts);
  if (new Set(normalized.map((account) => account.id)).size !== normalized.length) throw new Error(INVALID_DATA);
  const current = normalized.map((account) => {
    const previous = previousById.get(account.id)?.account;
    if (!previous || sameCredentials(previous, account)) return account;
    // Replacing credentials starts a new identity. It must not inherit an
    // independent copy's deletion or make older backups claim the replacement.
    const id = crypto.randomUUID();
    restorations.add(id);
    return { ...account, id };
  });
  const currentById = new Map(current.map((account) => [account.id, account]));
  let revision = Math.max(0, ...baseline.map((record) => record.revision));
  const nextRevision = () => {
    if (revision >= Number.MAX_SAFE_INTEGER) throw new Error(INVALID_DATA);
    return ++revision;
  };
  const changes: BrowserSyncRecord[] = [];

  for (const account of current) {
    const previous = previousById.get(account.id);
    const syncedAccount = withoutLocalOrder(account);
    const restorationId = restorations.has(account.id) ? account.id : previous?.restorationId;
    if (!previous || JSON.stringify(previous.account) !== JSON.stringify(syncedAccount) || restorationId !== previous.restorationId) {
      changes.push({
        id: account.id, revision: nextRevision(), deviceId: state.deviceId, account: syncedAccount,
        ...(restorationId ? { restorationId } : {})
      });
    }
  }
  for (const previous of baseline) {
    if (previous.account && !currentById.has(previous.id)) {
      changes.push({
        id: previous.id, revision: nextRevision(), deviceId: state.deviceId, account: null,
        ...(previous.restorationId ? { restorationId: previous.restorationId } : {})
      });
    }
  }

  const incoming = remoteRecords.map(normalizeSyncRecord);
  const candidates = [...baseline, ...changes, ...incoming];
  revision = Math.max(revision, ...candidates.map((record) => record.revision));
  // Earlier joins could save a combined counter under a remote revision. The
  // actual record for that revision tells us whether it still needs publishing.
  const candidateValues = new Set([...changes, ...incoming, ...baseline.filter((record) =>
    !incoming.some((other) => other.id === record.id && other.deviceId === record.deviceId && other.revision === record.revision)
  )].map((record) => JSON.stringify(record)));
  const merged = mergeSyncRecords(candidates).map((record) => {
    // Combined counters and identities need a revision in this device's slot.
    if (!candidateValues.has(JSON.stringify(record))) {
      return { ...record, revision: nextRevision(), deviceId: state.deviceId };
    }
    return record;
  });
  const surviving = new Map(merged.flatMap((record) => record.account ? [[record.id, record.account] as const] : []));
  const identities = indexSyncIdentities(merged);
  const accounts: AuthenticatorAccount[] = [];
  let nextOrder = current.reduce((maximum, account, index) => Math.max(maximum, account.sortOrder ?? index), -1) + 1;
  for (const account of current) {
    const id = identities.get(account.id)?.id ?? account.id;
    const survivor = surviving.get(id);
    if (survivor) accounts.push(account.sortOrder === undefined ? survivor : { ...survivor, sortOrder: account.sortOrder });
    surviving.delete(id);
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
    typeof value.revision !== 'number' || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
    (value.restorationId !== undefined && value.restorationId !== value.id) ||
    (value.origins !== undefined && (!Array.isArray(value.origins) || value.origins.some((origin) =>
      typeof origin !== 'string' || !/^[0-9a-f]{64}$/.test(origin)))) ||
    (value.mergedIds !== undefined && (!Array.isArray(value.mergedIds) || value.mergedIds.some((id) =>
      typeof id !== 'string' || !id.trim() || id.length > 512)))
  ) throw new Error(INVALID_DATA);

  const account = value.account === null ? null : withoutLocalOrder(normalizeImportedAccounts([value.account])[0]);
  if (account && (account.id !== value.id || !Number.isFinite(Date.parse(account.createdAt)) || !Number.isFinite(Date.parse(account.updatedAt)))) {
    throw new Error(INVALID_DATA);
  }
  const mergedIds = Array.from(new Set(value.mergedIds as string[] | undefined)).filter((id) => id !== value.id).sort(compareText);
  const origins = Array.from(new Set(value.origins as string[] | undefined)).sort(compareText);
  return {
    id: value.id, revision: value.revision, deviceId: value.deviceId, account,
    ...(mergedIds.length ? { mergedIds } : {}),
    ...(value.restorationId ? { restorationId: value.id } : {}),
    ...(origins.length ? { origins } : {})
  };
}

function recordIds(record: BrowserSyncRecord): string[] {
  return [record.id, ...(record.mergedIds ?? [])];
}

function recordsOverlap(left: BrowserSyncRecord, right: BrowserSyncRecord): boolean {
  return recordIds(left).some((id) => recordIds(right).includes(id)) ||
    Boolean(left.origins?.some((origin) => right.origins?.includes(origin)));
}

export async function withSyncOrigin(record: BrowserSyncRecord): Promise<BrowserSyncRecord> {
  const normalized = normalizeSyncRecord(record);
  if (!normalized.account || normalized.origins?.length) return normalized;
  const origins = new Set(normalized.origins);
  for (const origin of await Promise.all(recordIds(normalized).map((id) => accountOrigin({ ...normalized.account!, id })))) {
    origins.add(origin);
  }
  return { ...normalized, origins: Array.from(origins).sort(compareText) };
}

export async function withSyncOrigins(records: BrowserSyncRecord[], known: BrowserSyncRecord[] = []): Promise<BrowserSyncRecord[]> {
  const identities = indexSyncIdentities(mergeSyncRecords([...known, ...records]));
  return Promise.all(records.map((record) => {
    const origins = record.origins ?? identities.get(record.id)?.origins;
    return withSyncOrigin(origins ? { ...record, origins } : record);
  }));
}

export async function accountOrigin(account: AuthenticatorAccount): Promise<string> {
  return hash(JSON.stringify([
    'account-origin-v1', account.id, account.secret, account.type, account.algorithm, account.digits, account.period
  ]), 32);
}

function indexSyncIdentities(records: BrowserSyncRecord[]): Map<string, BrowserSyncRecord> {
  const aliases = [...records].sort((left, right) =>
    Number(Boolean(left.account)) - Number(Boolean(right.account)) || compareText(right.id, left.id));
  // Canonical identities own their IDs. Shared old aliases prefer a live restore.
  return new Map([
    ...aliases.flatMap((record) => (record.mergedIds ?? []).map((id) => [id, record] as const)),
    ...records.map((record) => [record.id, record] as const)
  ]);
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

async function hash(text: string, length = 16): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text)));
  return Array.from(digest.subarray(0, length), (byte) => byte.toString(16).padStart(2, '0')).join('');
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

function sameCredentials(left: AuthenticatorAccount, right: AuthenticatorAccount): boolean {
  return left.secret === right.secret && left.type === right.type && left.algorithm === right.algorithm &&
    left.digits === right.digits && left.period === right.period;
}

function withoutLocalOrder(account: AuthenticatorAccount): AuthenticatorAccount {
  const syncedAccount = { ...account };
  delete syncedAccount.sortOrder;
  return syncedAccount;
}
