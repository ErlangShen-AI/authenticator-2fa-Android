import { describe, expect, test } from 'vitest';
import {
  joinSyncAccounts,
  withSyncOrigin,
  withSyncOrigins,
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
    expect(await decryptSyncRecord(key, first.storageKey, first.value)).toEqual(await withSyncOrigin(record));
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
    const canonical = await withSyncOrigin({ ...record, mergedIds: ['a', 'z'] });
    expect(await decryptSyncRecord(key, item.storageKey, item.value)).toEqual(canonical);
    const deleted = await encryptSyncRecord(key, { ...record, account: null, mergedIds: ['z', 'a'] });
    const tombstone = await decryptSyncRecord(key, deleted.storageKey, deleted.value);
    expect(tombstone).toEqual({ ...record, account: null, mergedIds: ['a', 'z'] });
    expect((await withSyncOrigins([tombstone], [canonical]))[0].origins).toEqual(canonical.origins);
    const restored = await withSyncOrigin({ ...record, mergedIds: ['old-copy'], restorationId: record.id });
    const restoration = await encryptSyncRecord(key, restored);
    expect(await decryptSyncRecord(key, restoration.storageKey, restoration.value)).toEqual(restored);
    const restoredDeletion = await encryptSyncRecord(key, { ...restored, account: null });
    expect(await decryptSyncRecord(key, restoredDeletion.storageKey, restoredDeletion.value)).toEqual({ ...restored, account: null });
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
      { ...record, origins: 'invalid' },
      { ...record, origins: [null] },
      { ...record, origins: ['not-a-fingerprint'] },
      { ...record, restorationId: null },
      { ...record, restorationId: 'another-identity' },
      { ...record, restorationOrigin: 'a'.repeat(64) },
      { ...record, restorationId: record.id, restorationOrigin: null },
      { ...record, restorationId: record.id, restorationOrigin: 'not-a-fingerprint' },
      { ...record, restorationId: record.id, restorationOrigin: 'a'.repeat(64), origins: ['b'.repeat(64)] }
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
  test('conserves HOTP counters through overlapping duplicate sets on three devices', async () => {
    const copies = ['a', 'b', 'c'].map((id, index) => ({
      ...record, id, account: { ...account, id, type: 'hotp' as const, counter: index === 2 ? 100 : 1 }
    }));
    const left = await reconcileSyncAccounts(state(), copies.slice(0, 2).map((value) => value.account), []);
    const right = await reconcileSyncAccounts(state([], DEVICE_B), copies.slice(1).map((value) => value.account), []);
    const merged = await reconcileSyncAccounts(left.state, left.accounts, right.writes);
    expect(merged.accounts).toHaveLength(1);
    expect(merged.accounts[0]).toMatchObject({ id: 'a', counter: 100 });
    expect(merged.state.records.a).toMatchObject({ mergedIds: ['b', 'c'] });
    expect(merged.writes[0].account?.counter).toBe(100);
    expect(mergeSyncRecords([...left.writes, ...right.writes])).toEqual(mergeSyncRecords([...right.writes, ...left.writes]));
    expect((await reconcileSyncAccounts(right.state, right.accounts, merged.writes)).accounts[0]).toMatchObject({ id: 'a', counter: 100 });
  });

  test('retains duplicate identity links when either copy is later deleted', async () => {
    const copies = ['a', 'b'].map((id) => ({ ...account, id }));
    const local = await reconcileSyncAccounts(state(), [copies[1]], []);
    const joined = await reconcileSyncAccounts(local.state, local.accounts, [{
      ...record, id: copies[0].id, deviceId: DEVICE_B, account: copies[0]
    }]);
    const deleted = await reconcileSyncAccounts(joined.state, [], []);
    const stale = { ...record, id: 'b', revision: 100, account: { ...copies[1], label: 'Offline edit' } };
    expect((await reconcileSyncAccounts(deleted.state, [], [stale])).accounts).toEqual([]);
    expect((await reconcileSyncAccounts(joined.state, joined.accounts, [{ ...stale, account: null }])).accounts).toEqual([]);
    expect((await joinSyncAccounts(deleted.state, joined.accounts)).accounts).toEqual([]);
  });

  test('keeps merged identities after editing account details and retrying with stale copies', async () => {
    const copies = ['a', 'b'].map((id) => ({ ...account, id }));
    const joined = await reconcileSyncAccounts(state(), copies, []);
    // Older devices can replace credentials without rotating their account ID.
    const legacy = await reconcileSyncAccounts(joined.state, joined.accounts, [{
      ...record, id: 'a', revision: 10, account: { ...copies[0], secret: 'KRUGS4ZANFZSAYJA' }
    }]);
    const edited = await reconcileSyncAccounts(legacy.state, [{ ...legacy.accounts[0], label: 'Renamed' }], []);
    const stale = { ...record, id: 'b', account: copies[1] };
    expect(edited.state.records.a.mergedIds).toEqual(['b']);
    expect(edited.state.records.a.origins).toEqual(legacy.state.records.a.origins);
    expect(await reconcileSyncAccounts(edited.state, edited.accounts, [stale])).toEqual(edited);
  });

  test('adding an account again survives older duplicate records and their tombstone', async () => {
    const copies = ['a', 'b'].map((id) => ({ ...account, id }));
    const joined = await reconcileSyncAccounts(state(), copies, []);
    const deleted = await reconcileSyncAccounts(joined.state, [], []);
    const restored = { ...account, id: 'restored' };
    const result = await reconcileSyncAccounts(deleted.state, [restored], [{ ...record, id: 'b', account: copies[1] }]);
    expect(result.accounts).toEqual([restored]);
  });

  test('a restore survives an old live copy followed by its delayed tombstone', async () => {
    const original = { ...record, id: 'a', account: { ...account, id: 'a' } };
    const restored = { ...account, id: 'restored' };
    const imported = await reconcileSyncAccounts(state(), [restored], [], [restored.id]);
    const delivered = await reconcileSyncAccounts(imported.state, imported.accounts, [original]);
    expect(delivered.accounts).toEqual([restored]);
    expect(delivered.state.records[restored.id]).toMatchObject({ restorationId: restored.id, mergedIds: [original.id] });
    const deleted = await reconcileSyncAccounts(delivered.state, delivered.accounts, [{ ...original, account: null }]);
    expect(deleted.accounts).toEqual([restored]);
    expect(await reconcileSyncAccounts(deleted.state, deleted.accounts, [original])).toEqual(deleted);
  });

  test('joining copies converge on a restored identity and later deletion suppresses stale originals', async () => {
    const restored = { ...account, id: 'restored' };
    const imported = await reconcileSyncAccounts(state(), [restored], [], [restored.id]);
    const copy = { ...account, id: 'joining-copy' };
    const joined = await reconcileSyncAccounts(state([], DEVICE_B), [copy], []);
    const adopted = await reconcileSyncAccounts(joined.state, joined.accounts, imported.writes);
    expect(adopted.accounts.map((value) => value.id)).toEqual([restored.id]);
    const renamed = await reconcileSyncAccounts(adopted.state, [{ ...adopted.accounts[0], label: 'Renamed' }], []);
    expect(renamed.state.records[restored.id].restorationId).toBe(restored.id);
    const deleted = await reconcileSyncAccounts(renamed.state, [], []);
    expect(deleted.state.records[restored.id]).toMatchObject({ restorationId: restored.id, account: null });
    expect((await reconcileSyncAccounts(imported.state, imported.accounts, [...joined.writes, ...deleted.writes])).accounts).toEqual([]);
  });

  test('retains late old alias chains without transferring their deletion into a restore', async () => {
    const restored = { ...account, id: 'restored' };
    const imported = await reconcileSyncAccounts(state(), [restored], [], [restored.id]);
    const copy = { ...record, id: 'b', account: { ...account, id: 'b' } };
    const adopted = await reconcileSyncAccounts(imported.state, imported.accounts, [copy]);
    const oldDeletion = { ...copy, id: 'a', account: null, mergedIds: ['b'] };
    const delivered = await reconcileSyncAccounts(adopted.state, adopted.accounts, [oldDeletion]);
    expect(delivered.accounts).toEqual([restored]);
    expect(delivered.state.records[restored.id].mergedIds).toEqual(['a', 'b']);
    const stale = { ...copy, id: 'a', account: { ...copy.account, id: 'a' } };
    const repeated = await reconcileSyncAccounts(delivered.state, delivered.accounts, [stale]);
    expect(repeated.accounts).toEqual([restored]);
    expect(await reconcileSyncAccounts(repeated.state, repeated.accounts, [stale])).toEqual(repeated);
  });

  test('keeps explicit restore generations independent when an earlier generation is deleted', async () => {
    const copies = ['restore-a', 'restore-b'].map((id) => ({ ...account, id }));
    const first = await reconcileSyncAccounts(state(), [copies[0]], [], [copies[0].id]);
    const second = await reconcileSyncAccounts(state([], DEVICE_B), [copies[1]], [], [copies[1].id]);
    const deleted = await reconcileSyncAccounts(first.state, [], []);
    const result = await reconcileSyncAccounts(second.state, second.accounts, [...first.writes, ...deleted.writes]);
    expect(result.accounts).toEqual([copies[1]]);
  });

  test('keeps accounts with different secrets, names, or OTP settings distinct', async () => {
    const variants = [
      {}, { secret: 'KRUGS4ZANFZSAYJA' }, { issuer: 'Other' }, { label: 'Other' },
      { algorithm: 'SHA-256' as const }, { digits: 8 as const }, { period: 60 }, { type: 'hotp' as const }
    ].map((patch, index) => ({ ...account, ...patch, id: `copy-${index}` }));
    expect((await reconcileSyncAccounts(state(), variants, [])).accounts).toEqual(variants);
  });

  test('initial upload publishes local accounts; an unseen remote account is never deleted', async () => {
    const local = createAccount({ label: 'Local', secret: account.secret });
    const result = await reconcileSyncAccounts(state(), [local], [record]);
    expect(new Set(result.accounts.map((value) => value.id))).toEqual(new Set([local.id, account.id]));
    expect(result.writes).toHaveLength(2); // both records belong to this fixture's device
    expect(result.writes.every((value) => value.account !== null)).toBe(true);
  });

  test('compares local edits to the applied baseline before merging incoming edits', async () => {
    const remote = { ...record, revision: 2, deviceId: DEVICE_B, account: { ...account, label: 'Remote' } };
    const result = await reconcileSyncAccounts(state([record]), [{ ...account, label: 'Local' }], [remote]);
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

  test('makes deletions permanent even after a stale offline edit has a higher revision', async () => {
    const deletion = { ...record, revision: 2, account: null };
    const offline = { ...record, revision: 100, deviceId: DEVICE_B, account: { ...account, label: 'Offline' } };
    expect(mergeSyncRecords([offline, deletion])[0]).toEqual(deletion);
    const result = await reconcileSyncAccounts(state([record]), [], [offline]);
    expect(result.accounts).toEqual([]);
    expect(result.writes[0].account).toBeNull();
  });

  test('retains tombstones after all remote account slots temporarily disappear', async () => {
    const deletion = { ...record, revision: 2, account: null };
    const result = await reconcileSyncAccounts(state([deletion]), [], []);
    expect(result.state.records[account.id]).toEqual(deletion);
    expect(result.writes).toEqual([deletion]);
  });

  test('retains local winners for retry after a failed upload and does not create extra revisions', async () => {
    const initial = await reconcileSyncAccounts(state(), [account], []);
    const retry = await reconcileSyncAccounts(initial.state, initial.accounts, []);
    expect(retry).toEqual(initial);
    expect(() => structuredClone(retry.state)).not.toThrow();
  });

  test('keeps ordering local and appends incoming accounts without generating reorder writes', async () => {
    const initial = await reconcileSyncAccounts(state(), [{ ...account, sortOrder: 7 }], []);
    const reordered = await reconcileSyncAccounts(initial.state, [{ ...account, sortOrder: 0 }], []);
    expect(reordered.state).toEqual(initial.state);
    expect(reordered.writes).toEqual(initial.writes);
    expect(reordered.accounts[0].sortOrder).toBe(0);
    expect(reordered.writes[0].account).not.toHaveProperty('sortOrder');
    const encrypted = await encryptSyncRecord(initial.state.recoveryKey, { ...record, account: { ...account, sortOrder: 42 } });
    const decrypted = await decryptSyncRecord(initial.state.recoveryKey, encrypted.storageKey, encrypted.value);
    expect(decrypted.account).not.toHaveProperty('sortOrder');

    const incoming = createAccount({ label: 'Incoming', secret: account.secret });
    const merged = await reconcileSyncAccounts(initial.state, initial.accounts, [{ ...record, id: incoming.id, account: incoming, deviceId: DEVICE_B }]);
    expect(merged.accounts.map((value) => value.sortOrder)).toEqual([7, 8]);
    expect((await reconcileSyncAccounts(merged.state, merged.accounts, [])).state).toEqual(merged.state);
  });

  test('preserves the largest HOTP counter through concurrent renames and emits a new local revision', async () => {
    const hotp = { ...account, type: 'hotp' as const, counter: 50 };
    const baseline = { ...record, account: hotp };
    const remote = { ...record, revision: 2, deviceId: DEVICE_B, account: { ...hotp, label: 'Renamed', counter: 20 } };
    const result = await reconcileSyncAccounts(state([baseline]), [hotp], [remote]);
    expect(result.accounts[0]).toMatchObject({ label: 'Renamed', counter: 50 });
    expect(result.writes[0]).toMatchObject({ revision: 3, deviceId: DEVICE_A });
    const repeat = await reconcileSyncAccounts(result.state, result.accounts, [baseline, remote]);
    expect(repeat).toEqual(result);
  });

  test('republishes an older join baseline whose merged counter was never uploaded', async () => {
    const remote = { ...record, deviceId: DEVICE_B, account: { ...account, type: 'hotp' as const, counter: 1 } };
    const synthetic = { ...remote, account: { ...remote.account, counter: 100 } };
    const repaired = await reconcileSyncAccounts(state([synthetic]), [synthetic.account], [remote]);
    expect(repaired.writes).toHaveLength(1);
    expect(repaired.writes[0]).toMatchObject({ revision: 2, deviceId: DEVICE_A, account: { counter: 100 } });
    expect(await reconcileSyncAccounts(repaired.state, repaired.accounts, [remote])).toEqual(repaired);
  });

  test('never carries a counter across a replacement secret or algorithm', () => {
    const old = { ...record, account: { ...account, type: 'hotp' as const, counter: 50 } };
    for (const patch of [{ secret: 'KRUGS4ZANFZSAYJA' }, { algorithm: 'SHA-256' as const }]) {
      const next = { ...record, revision: 2, account: { ...old.account, ...patch, counter: 1 } };
      expect(mergeSyncRecords([old, next])[0].account?.counter).toBe(1);
    }
  });

  test('supports identifiers that are special JavaScript object property names', async () => {
    const special = { ...account, id: '__proto__' };
    const result = await reconcileSyncAccounts(state(), [special], []);
    expect(Object.hasOwn(result.state.records, '__proto__')).toBe(true);
    expect(result.accounts).toEqual([special]);
    expect((await reconcileSyncAccounts(result.state, [], [])).accounts).toEqual([]);
  });

  test('rejects revision overflow and duplicate local IDs without changing the baseline', async () => {
    const exhausted = state([{ ...record, revision: Number.MAX_SAFE_INTEGER }]);
    const before = structuredClone(exhausted);
    await expect(reconcileSyncAccounts(exhausted, [], [])).rejects.toThrow();
    expect(exhausted).toEqual(before);
    await expect(reconcileSyncAccounts(state(), [account, account], [])).rejects.toThrow();
  });
});

describe('joining an existing Browser Sync group', () => {
  test('deduplicates matching accounts with different IDs and keeps remote account details', async () => {
    const local = { ...account, id: 'z-local', label: account.label.toUpperCase(), createdAt: '2025-01-01T00:00:00.000Z' };
    const distinct = createAccount({ label: 'Separate', secret: account.secret });
    const result = await joinSyncAccounts(state([record], DEVICE_B), [local, distinct]);
    expect(result.accounts).toEqual([
      { ...account, id: expect.any(String) },
      { ...distinct, id: expect.any(String) }
    ]);
  });

  test('does not link a conflicting alias to another matching remote credential', async () => {
    const original = { ...record, mergedIds: ['old-copy'] };
    const otherAccount = { ...account, id: 'other', secret: 'KRUGS4ZANFZSAYJA' };
    const other = { ...record, id: otherAccount.id, account: otherAccount };
    const joined = await joinSyncAccounts(state([original, other], DEVICE_B), [{ ...otherAccount, id: 'old-copy' }]);

    expect(joined.accounts.map((item) => item.secret).sort()).toEqual([account.secret, otherAccount.secret].sort());
    const deleted = await reconcileSyncAccounts(joined.state, [account], []);
    expect(deleted.accounts).toEqual([account]);
  });

  test('preserves a larger local HOTP counter without mutating remote records', async () => {
    const remote = { ...record, account: { ...account, type: 'hotp' as const, counter: 5 } };
    const local = { ...remote.account, id: 'z-local', counter: 20 };
    const before = structuredClone(remote);
    const { accounts: aligned } = await joinSyncAccounts(state([remote], DEVICE_B), [local]);
    expect(aligned).toEqual([{ ...remote.account, id: expect.any(String), counter: 20 }]);
    expect(remote).toEqual(before);
  });

  test('distinguishes deleted copies from independently changed credentials when joining', async () => {
    const synced = await withSyncOrigin(record);
    const deleted = state([{ ...synced, account: null }]);
    expect((await joinSyncAccounts(deleted, [account])).accounts).toEqual([]);
    const changed = { ...account, secret: 'KRUGS4ZANFZSAYJA' };
    expect((await joinSyncAccounts(deleted, [changed])).accounts).toEqual([{ ...changed, id: expect.any(String) }]);
  });

  test('adopts a known merged identity and respects its deletion even after a local rename', async () => {
    const remote = await withSyncOrigin({ ...record, mergedIds: ['old-copy'] });
    const local = { ...account, id: 'old-copy', label: 'Local rename', sortOrder: 3 };
    expect((await joinSyncAccounts(state([remote]), [local])).accounts).toEqual([{ ...account, sortOrder: 3 }]);
    const deleted = { ...remote, account: null };
    expect((await joinSyncAccounts(state([deleted]), [local])).accounts).toEqual([]);
  });

  test('a deleted restoration cannot hide a live restoration that shares an earlier copy', async () => {
    const hotp = { ...account, id: 'a-live', type: 'hotp' as const, counter: 5 };
    const live = { ...record, id: hotp.id, account: hotp, restorationId: hotp.id, mergedIds: ['old-copy'] };
    const deleted = { ...record, id: 'z-deleted', account: null, restorationId: 'z-deleted', mergedIds: ['old-copy', hotp.id] };
    for (const id of ['old-copy', hotp.id]) {
      const local = { ...hotp, id, counter: 100, sortOrder: 3 };
      expect((await joinSyncAccounts(state([live, deleted]), [local])).accounts).toEqual([{ ...hotp, counter: 100, sortOrder: 3 }]);
    }
  });
});
