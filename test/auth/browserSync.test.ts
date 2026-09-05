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

  test('authenticates duplicate identities and stores them in a canonical form', async () => {
    const key = generateSyncRecoveryKey();
    const item = await encryptSyncRecord(key, { ...record, mergedIds: ['z', 'a', 'z', record.id] });
    expect(await decryptSyncRecord(key, item.storageKey, item.value)).toEqual({ ...record, mergedIds: ['a', 'z'] });
    const deleted = await encryptSyncRecord(key, { ...record, account: null, mergedIds: ['z', 'a'] });
    expect(await decryptSyncRecord(key, deleted.storageKey, deleted.value)).toEqual({ ...record, account: null, mergedIds: ['a', 'z'] });
    const restored = { ...record, mergedIds: ['old-copy'], restorationId: record.id };
    const restoration = await encryptSyncRecord(key, restored);
    expect(await decryptSyncRecord(key, restoration.storageKey, restoration.value)).toEqual(restored);
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
      { ...record, account: { ...account, createdAt: 'invalid' } },
      { ...record, mergedIds: 'other' },
      { ...record, mergedIds: null },
      { ...record, mergedIds: [null] },
      { ...record, mergedIds: [''] },
      { ...record, mergedIds: ['a'.repeat(513)] },
      { ...record, restorationId: null },
      { ...record, restorationId: 'another-identity' }
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
  test('conserves HOTP counters through overlapping duplicate sets on three devices', () => {
    const copies = ['a', 'b', 'c'].map((id, index) => ({
      ...record, id, account: { ...account, id, type: 'hotp' as const, counter: index === 2 ? 100 : 1 }
    }));
    const left = reconcileSyncAccounts(state(), copies.slice(0, 2).map((value) => value.account), []);
    const right = reconcileSyncAccounts(state([], DEVICE_B), copies.slice(1).map((value) => value.account), []);
    const merged = reconcileSyncAccounts(left.state, left.accounts, right.writes);
    expect(merged.accounts).toHaveLength(1);
    expect(merged.accounts[0]).toMatchObject({ id: 'a', counter: 100 });
    expect(merged.state.records.a).toMatchObject({ mergedIds: ['b', 'c'] });
    expect(merged.writes[0].account?.counter).toBe(100);
    expect(mergeSyncRecords([...left.writes, ...right.writes])).toEqual(mergeSyncRecords([...right.writes, ...left.writes]));
    expect(reconcileSyncAccounts(right.state, right.accounts, merged.writes).accounts[0]).toMatchObject({ id: 'a', counter: 100 });
  });

  test('retains duplicate identity links when either copy is later deleted', () => {
    const copies = ['a', 'b'].map((id) => ({ ...account, id }));
    const joined = reconcileSyncAccounts(state(), copies, []);
    const deleted = reconcileSyncAccounts(joined.state, [], []);
    const stale = { ...record, id: 'b', revision: 100, account: { ...copies[1], label: 'Offline edit' } };
    expect(reconcileSyncAccounts(deleted.state, [], [stale]).accounts).toEqual([]);
    expect(reconcileSyncAccounts(joined.state, joined.accounts, [{ ...stale, account: null }]).accounts).toEqual([]);
  });

  test('keeps merged identities after editing account details and retrying with stale copies', () => {
    const copies = ['a', 'b'].map((id) => ({ ...account, id }));
    const joined = reconcileSyncAccounts(state(), copies, []);
    const edited = reconcileSyncAccounts(joined.state, [{ ...joined.accounts[0], label: 'Renamed' }], []);
    const stale = { ...record, id: 'b', account: copies[1] };
    expect(edited.state.records.a.mergedIds).toEqual(['b']);
    expect(reconcileSyncAccounts(edited.state, edited.accounts, [stale])).toEqual(edited);
  });

  test('adding an account again survives older duplicate records and their tombstone', () => {
    const copies = ['a', 'b'].map((id) => ({ ...account, id }));
    const joined = reconcileSyncAccounts(state(), copies, []);
    const deleted = reconcileSyncAccounts(joined.state, [], []);
    const restored = { ...account, id: 'restored' };
    const result = reconcileSyncAccounts(deleted.state, [restored], [{ ...record, id: 'b', account: copies[1] }]);
    expect(result.accounts).toEqual([restored]);
  });

  test('a restore survives an old live copy followed by its delayed tombstone', () => {
    const original = { ...record, id: 'a', account: { ...account, id: 'a' } };
    const restored = { ...account, id: 'restored' };
    const imported = reconcileSyncAccounts(state(), [restored], [], [restored.id]);
    const delivered = reconcileSyncAccounts(imported.state, imported.accounts, [original]);
    expect(delivered.accounts).toEqual([restored]);
    expect(delivered.state.records[restored.id]).toMatchObject({ restorationId: restored.id, mergedIds: [original.id] });
    const deleted = reconcileSyncAccounts(delivered.state, delivered.accounts, [{ ...original, account: null }]);
    expect(deleted.accounts).toEqual([restored]);
    expect(reconcileSyncAccounts(deleted.state, deleted.accounts, [original])).toEqual(deleted);
  });

  test('joining copies converge on a restored identity and later deletion suppresses stale originals', () => {
    const restored = { ...account, id: 'restored' };
    const imported = reconcileSyncAccounts(state(), [restored], [], [restored.id]);
    const copy = { ...account, id: 'joining-copy' };
    const joined = reconcileSyncAccounts(state([], DEVICE_B), [copy], []);
    const adopted = reconcileSyncAccounts(joined.state, joined.accounts, imported.writes);
    expect(adopted.accounts.map((value) => value.id)).toEqual([restored.id]);
    const renamed = reconcileSyncAccounts(adopted.state, [{ ...adopted.accounts[0], label: 'Renamed' }], []);
    expect(renamed.state.records[restored.id].restorationId).toBe(restored.id);
    const deleted = reconcileSyncAccounts(renamed.state, [], []);
    expect(deleted.state.records[restored.id]).toMatchObject({ restorationId: restored.id, account: null });
    expect(reconcileSyncAccounts(imported.state, imported.accounts, [...joined.writes, ...deleted.writes]).accounts).toEqual([]);
  });

  test('retains late old alias chains without transferring their deletion into a restore', () => {
    const restored = { ...account, id: 'restored' };
    const imported = reconcileSyncAccounts(state(), [restored], [], [restored.id]);
    const copy = { ...record, id: 'b', account: { ...account, id: 'b' } };
    const adopted = reconcileSyncAccounts(imported.state, imported.accounts, [copy]);
    const oldDeletion = { ...copy, id: 'a', account: null, mergedIds: ['b'] };
    const delivered = reconcileSyncAccounts(adopted.state, adopted.accounts, [oldDeletion]);
    expect(delivered.accounts).toEqual([restored]);
    expect(delivered.state.records[restored.id].mergedIds).toEqual(['a', 'b']);
    expect(reconcileSyncAccounts(delivered.state, delivered.accounts, [{ ...copy, id: 'a', account: { ...copy.account, id: 'a' } }])).toEqual(delivered);
  });

  test('keeps explicit restore generations independent when an earlier generation is deleted', () => {
    const copies = ['restore-a', 'restore-b'].map((id) => ({ ...account, id }));
    const first = reconcileSyncAccounts(state(), [copies[0]], [], [copies[0].id]);
    const second = reconcileSyncAccounts(state([], DEVICE_B), [copies[1]], [], [copies[1].id]);
    const deleted = reconcileSyncAccounts(first.state, [], []);
    const result = reconcileSyncAccounts(second.state, second.accounts, [...first.writes, ...deleted.writes]);
    expect(result.accounts).toEqual([copies[1]]);
  });

  test('keeps accounts with different secrets, names, or OTP settings distinct', () => {
    const variants = [
      {}, { secret: 'KRUGS4ZANFZSAYJA' }, { issuer: 'Other' }, { label: 'Other' },
      { algorithm: 'SHA-256' as const }, { digits: 8 as const }, { period: 60 }, { type: 'hotp' as const }
    ].map((patch, index) => ({ ...account, ...patch, id: `copy-${index}` }));
    expect(reconcileSyncAccounts(state(), variants, []).accounts).toEqual(variants);
  });

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

  test('republishes an older join baseline whose merged counter was never uploaded', () => {
    const remote = { ...record, deviceId: DEVICE_B, account: { ...account, type: 'hotp' as const, counter: 1 } };
    const synthetic = { ...remote, account: { ...remote.account, counter: 100 } };
    const repaired = reconcileSyncAccounts(state([synthetic]), [synthetic.account], [remote]);
    expect(repaired.writes).toHaveLength(1);
    expect(repaired.writes[0]).toMatchObject({ revision: 2, deviceId: DEVICE_A, account: { counter: 100 } });
    expect(reconcileSyncAccounts(repaired.state, repaired.accounts, [remote])).toEqual(repaired);
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

  test('adopts a known merged identity and respects its deletion even after a local rename', () => {
    const remote = { ...record, mergedIds: ['old-copy'] };
    const local = { ...account, id: 'old-copy', label: 'Local rename', sortOrder: 3 };
    expect(alignSyncAccounts([local], [remote])).toEqual([{ ...account, sortOrder: 3 }]);
    expect(alignSyncAccounts([local], [{ ...remote, account: null }])).toEqual([]);
  });

  test('a deleted restoration cannot hide a live restoration that shares an earlier copy', () => {
    const hotp = { ...account, id: 'a-live', type: 'hotp' as const, counter: 5 };
    const live = { ...record, id: hotp.id, account: hotp, restorationId: hotp.id, mergedIds: ['old-copy'] };
    const deleted = { ...record, id: 'z-deleted', account: null, restorationId: 'z-deleted', mergedIds: ['old-copy', hotp.id] };
    for (const id of ['old-copy', hotp.id]) {
      const local = { ...hotp, id, counter: 100, sortOrder: 3 };
      expect(alignSyncAccounts([local], [live, deleted])).toEqual([{ ...hotp, counter: 100, sortOrder: 3 }]);
    }
  });
});
