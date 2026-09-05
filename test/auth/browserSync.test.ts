import { describe, expect, test } from 'vitest';
import {
  alignSyncAccounts,
  createSyncMarker,
  decryptSyncRecord,
  encryptSyncRecord,
  generateSyncRecoveryKey,
  getSyncMarkerKey,
  getSyncNamespace,
  mergeSyncRecords,
  parseSyncRecoveryKey,
  reconcileSyncAccounts,
  validateSyncMarker,
  type BrowserSyncRecord,
  type BrowserSyncState
} from '../../src/lib/auth/browserSync';
import { bytesToBase64, decodeBase32 } from '../../src/lib/auth/base32';
import { createAccount } from '../../src/lib/auth/otp';

const DEVICE_A = '00000000-0000-4000-8000-000000000001';
const DEVICE_B = '00000000-0000-4000-8000-000000000002';
const account = createAccount({ issuer: 'Example', label: 'alice@example.com', secret: 'JBSWY3DPEHPK3PXP' });
const record: BrowserSyncRecord = { id: account.id, revision: 1, deviceId: DEVICE_A, account };

function state(records: BrowserSyncRecord[] = [], deviceId = DEVICE_A): BrowserSyncState {
  return {
    recoveryKey: generateSyncRecoveryKey(),
    deviceId,
    records: Object.fromEntries(records.map((value) => [value.id, value]))
  };
}

describe('Browser Sync encryption', () => {
  test('generates canonical 256-bit recovery keys and accepts pasted formatting', () => {
    const key = generateSyncRecoveryKey();
    expect(key).toMatch(/^A2FA1(?:-[A-Z2-7]{4}){13}$/);
    expect(parseSyncRecoveryKey(`  ${key.toLowerCase().replace(/-/g, ' ')}\n`)).toBe(key);
    expect(decodeBase32(key.replace(/-/g, '').slice(5))).toHaveLength(32);
    expect(generateSyncRecoveryKey()).not.toBe(key);
  });

  test.each(['', 'password123', `A2FA1-${'A'.repeat(51)}`, `A2FA1-${'A'.repeat(51)}B`])('rejects malformed recovery key %j', (key) => {
    expect(() => parseSyncRecoveryKey(key)).toThrow('recovery key is not valid');
  });

  test('encrypts all account metadata and changes ciphertext on each write', async () => {
    const key = generateSyncRecoveryKey();
    const first = await encryptSyncRecord(key, record);
    const second = await encryptSyncRecord(key, record);
    expect(first.storageKey).toBe(second.storageKey);
    expect(first.value.data).not.toBe(second.value.data);
    expect(first.value.iv).not.toBe(second.value.iv);
    expect(await decryptSyncRecord(key, first.storageKey, first.value)).toEqual(record);
    for (const privateValue of [account.id, account.issuer, account.label, account.secret, key]) {
      expect(JSON.stringify(first)).not.toContain(privateValue);
    }
  });

  test('uses distinct slots for independent device writes and supports imported arbitrary IDs', async () => {
    const key = generateSyncRecoveryKey();
    const imported = { ...account, id: 'alice@example.com / __proto__' };
    const first = await encryptSyncRecord(key, { ...record, id: imported.id, account: imported });
    const second = await encryptSyncRecord(key, { ...record, id: imported.id, account: imported, deviceId: DEVICE_B });
    expect(first.storageKey).not.toBe(second.storageKey);
    expect(first.storageKey).not.toContain(imported.id);
    expect((await decryptSyncRecord(key, first.storageKey, first.value)).account).toEqual(imported);
  });

  test('rejects wrong keys, tampering, and ciphertext moved to a different slot', async () => {
    const key = generateSyncRecoveryKey();
    const item = await encryptSyncRecord(key, record);
    await expect(decryptSyncRecord(generateSyncRecoveryKey(), item.storageKey, item.value)).rejects.toThrow();
    const tampered = { ...item.value, data: `${item.value.data[0] === 'A' ? 'B' : 'A'}${item.value.data.slice(1)}` };
    await expect(decryptSyncRecord(key, item.storageKey, tampered)).rejects.toThrow();
    await expect(decryptSyncRecord(key, item.storageKey.replace(DEVICE_A, DEVICE_B), item.value)).rejects.toThrow();
  });

  test('authenticates an empty group marker and separates key namespaces', async () => {
    const key = generateSyncRecoveryKey();
    const marker = await createSyncMarker(key);
    expect(marker.storageKey).toBe(await getSyncMarkerKey(key));
    await expect(validateSyncMarker(key, marker.value)).resolves.toBeUndefined();
    await expect(validateSyncMarker(generateSyncRecoveryKey(), marker.value)).rejects.toThrow();
    expect(await getSyncNamespace(key)).not.toBe(await getSyncNamespace(generateSyncRecoveryKey()));
    await expect(decryptSyncRecord(key, marker.storageKey, marker.value)).rejects.toThrow();
  });

  test.each([
    null,
    { version: 2, iv: 'A'.repeat(16), data: 'A'.repeat(24) },
    { version: 1, iv: 'A'.repeat(12), data: 'A'.repeat(24) },
    { version: 1, iv: 'A'.repeat(16), data: 'A'.repeat(9000) },
    { version: 1, iv: 'A'.repeat(16), data: '!'.repeat(24) }
  ])('rejects malformed envelopes before accepting any data', async (value) => {
    const key = generateSyncRecoveryKey();
    const item = await encryptSyncRecord(key, record);
    await expect(decryptSyncRecord(key, item.storageKey, value)).rejects.toThrow();
  });

  test('strictly validates authenticated plaintext instead of trusting encryption alone', async () => {
    const key = generateSyncRecoveryKey();
    const item = await encryptSyncRecord(key, record);
    const rawKey = decodeBase32(key.replace(/-/g, '').slice(5));
    const cryptoKey = await crypto.subtle.importKey('raw', new Uint8Array(rawKey), 'AES-GCM', false, ['encrypt']);
    const invalidPayloads = [
      { ...record, revision: Number.MAX_SAFE_INTEGER + 1 },
      { ...record, revision: -1 },
      { ...record, deviceId: DEVICE_B },
      { ...record, account: { ...account, id: crypto.randomUUID() } },
      { ...record, account: { ...account, counter: 1.5 } },
      { ...record, account: { ...account, counter: Number.MAX_SAFE_INTEGER + 1 } },
      { ...record, account: { ...account, algorithm: 'MD5' } },
      { ...record, account: { ...account, createdAt: 'invalid' } }
    ];
    for (const payload of invalidPayloads) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(item.storageKey) },
        cryptoKey,
        new TextEncoder().encode(JSON.stringify(payload))
      );
      await expect(decryptSyncRecord(key, item.storageKey, {
        version: 1, iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(encrypted))
      })).rejects.toThrow();
    }
  });

  test('rejects oversized account items without changing the original account', async () => {
    const oversized = { ...account, label: '界'.repeat(2500) };
    const before = structuredClone(oversized);
    await expect(encryptSyncRecord(generateSyncRecoveryKey(), { ...record, account: oversized })).rejects.toThrow('storage limit');
    expect(oversized).toEqual(before);
  });
});

describe('Browser Sync reconciliation', () => {
  test('initial upload publishes local accounts; an unseen remote account is never deleted', () => {
    const local = createAccount({ label: 'Local', secret: account.secret });
    const result = reconcileSyncAccounts(state(), [local], [record]);
    expect(new Set(result.accounts.map((value) => value.id))).toEqual(new Set([local.id, account.id]));
    expect(result.writes).toHaveLength(2); // both records belong to this fixture's device
    expect(result.writes.every((value) => value.account !== null)).toBe(true);
  });

  test('compares local edits to the applied baseline before merging incoming edits', () => {
    const remote = { ...record, revision: 2, deviceId: DEVICE_B, account: { ...account, label: 'Remote' } };
    const result = reconcileSyncAccounts(state([record]), [{ ...account, label: 'Local' }], [remote]);
    expect(result.accounts[0].label).toBe('Remote');
    expect(result.state.records[account.id].revision).toBe(2);
  });

  test('converges regardless of arrival order and uses revisions rather than timestamps', () => {
    const old = { ...record, account: { ...account, updatedAt: '2099-01-01T00:00:00.000Z' } };
    const a = { ...record, revision: 2, account: { ...account, label: 'A' } };
    const b = { ...a, deviceId: DEVICE_B, account: { ...account, label: 'B' } };
    const merged = mergeSyncRecords([old, a, b]);
    expect(merged).toEqual(mergeSyncRecords([b, a, old]));
    expect(merged).toEqual(mergeSyncRecords([...merged, old, a, b]));
    expect(merged[0].account?.label).toBe('B');
  });

  test('makes deletions permanent even after a stale offline edit has a higher revision', () => {
    const deletion = { ...record, revision: 2, account: null };
    const offline = { ...record, revision: 100, deviceId: DEVICE_B, account: { ...account, label: 'Offline' } };
    expect(mergeSyncRecords([offline, deletion])[0]).toEqual(deletion);
    const result = reconcileSyncAccounts(state([record]), [], [offline]);
    expect(result.accounts).toEqual([]);
    expect(result.writes[0].account).toBeNull();
  });

  test('retains tombstones after all remote account slots temporarily disappear', () => {
    const deletion = { ...record, revision: 2, account: null };
    const result = reconcileSyncAccounts(state([deletion]), [], []);
    expect(result.state.records[account.id]).toEqual(deletion);
    expect(result.writes).toEqual([deletion]);
  });

  test('retains local winners for retry after a failed upload and does not create extra revisions', () => {
    const initial = reconcileSyncAccounts(state(), [account], []);
    const retry = reconcileSyncAccounts(initial.state, initial.accounts, []);
    expect(retry).toEqual(initial);
    expect(() => structuredClone(retry.state)).not.toThrow();
  });

  test('keeps ordering local and appends incoming accounts without generating reorder writes', async () => {
    const initial = reconcileSyncAccounts(state(), [{ ...account, sortOrder: 7 }], []);
    const reordered = reconcileSyncAccounts(initial.state, [{ ...account, sortOrder: 0 }], []);
    expect(reordered.state).toEqual(initial.state);
    expect(reordered.writes).toEqual(initial.writes);
    expect(reordered.accounts[0].sortOrder).toBe(0);
    expect(reordered.writes[0].account).not.toHaveProperty('sortOrder');
    const encrypted = await encryptSyncRecord(initial.state.recoveryKey, { ...record, account: { ...account, sortOrder: 42 } });
    const decrypted = await decryptSyncRecord(initial.state.recoveryKey, encrypted.storageKey, encrypted.value);
    expect(decrypted.account).not.toHaveProperty('sortOrder');

    const incoming = createAccount({ label: 'Incoming', secret: account.secret });
    const merged = reconcileSyncAccounts(initial.state, initial.accounts, [{ ...record, id: incoming.id, account: incoming, deviceId: DEVICE_B }]);
    expect(merged.accounts.map((value) => value.sortOrder)).toEqual([7, 8]);
    expect(reconcileSyncAccounts(merged.state, merged.accounts, []).state).toEqual(merged.state);
  });

  test('preserves the largest HOTP counter through concurrent renames and emits a new local revision', () => {
    const hotp = { ...account, type: 'hotp' as const, counter: 50 };
    const baseline = { ...record, account: hotp };
    const remote = { ...record, revision: 2, deviceId: DEVICE_B, account: { ...hotp, label: 'Renamed', counter: 20 } };
    const result = reconcileSyncAccounts(state([baseline]), [hotp], [remote]);
    expect(result.accounts[0]).toMatchObject({ label: 'Renamed', counter: 50 });
    expect(result.writes[0]).toMatchObject({ revision: 3, deviceId: DEVICE_A });
    const repeat = reconcileSyncAccounts(result.state, result.accounts, [baseline, remote]);
    expect(repeat).toEqual(result);
  });

  test('never carries a counter across a replacement secret or algorithm', () => {
    const old = { ...record, account: { ...account, type: 'hotp' as const, counter: 50 } };
    for (const patch of [{ secret: 'KRUGS4ZANFZSAYJA' }, { algorithm: 'SHA-256' as const }]) {
      const next = { ...record, revision: 2, account: { ...old.account, ...patch, counter: 1 } };
      expect(mergeSyncRecords([old, next])[0].account?.counter).toBe(1);
    }
  });

  test('supports identifiers that are special JavaScript object property names', () => {
    const special = { ...account, id: '__proto__' };
    const result = reconcileSyncAccounts(state(), [special], []);
    expect(Object.hasOwn(result.state.records, '__proto__')).toBe(true);
    expect(result.accounts).toEqual([special]);
    expect(reconcileSyncAccounts(result.state, [], []).accounts).toEqual([]);
  });

  test('rejects revision overflow and duplicate local IDs without changing the baseline', () => {
    const exhausted = state([{ ...record, revision: Number.MAX_SAFE_INTEGER }]);
    const before = structuredClone(exhausted);
    expect(() => reconcileSyncAccounts(exhausted, [], [])).toThrow();
    expect(exhausted).toEqual(before);
    expect(() => reconcileSyncAccounts(state(), [account, account], [])).toThrow();
  });
});

describe('joining an existing Browser Sync group', () => {
  test('deduplicates matching accounts with different IDs and keeps remote account details', () => {
    const local = { ...account, id: crypto.randomUUID(), label: account.label.toUpperCase(), createdAt: '2025-01-01T00:00:00.000Z' };
    const distinct = createAccount({ label: 'Separate', secret: account.secret });
    const aligned = alignSyncAccounts([local, distinct], [record]);
    expect(aligned).toEqual([account, distinct]);
    const result = reconcileSyncAccounts(state([record], DEVICE_B), aligned, [record]);
    expect(result.writes).toHaveLength(1);
    expect(result.writes[0].id).toBe(distinct.id);
  });

  test('preserves a larger local HOTP counter while adopting the existing remote ID', () => {
    const remote = { ...record, account: { ...account, type: 'hotp' as const, counter: 5 } };
    const local = { ...remote.account, id: crypto.randomUUID(), counter: 20 };
    const before = structuredClone(remote);
    const aligned = alignSyncAccounts([local], [remote]);
    expect(aligned).toEqual([{ ...remote.account, counter: 20 }]);
    expect(remote).toEqual(before);
  });

  test('does not revive a previously deleted account on a device joining with an old backup', () => {
    expect(alignSyncAccounts([account], [{ ...record, account: null }])).toEqual([]);
  });
});
