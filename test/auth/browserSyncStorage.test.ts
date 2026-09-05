import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  SYNC_PREFIX,
  createSyncMarker,
  encryptSyncRecord,
  generateSyncRecoveryKey,
  getSyncNamespace
} from '../../src/lib/auth/browserSync';
import { connectBrowserSync, deleteBrowserSyncGroup, prepareBrowserSync } from '../../src/lib/auth/browserSyncSession';
import {
  browserSyncAvailable,
  readBrowserSyncItems,
  writeBrowserSyncItems
} from '../../src/lib/auth/browserSyncStorage';
import { createAccount } from '../../src/lib/auth/otp';

function installSyncStorage(initial: Record<string, unknown> = {}) {
  const values: Record<string, unknown> = structuredClone(initial);
  const runtime: { lastError?: { message: string } } = {};
  let failure: string | undefined;
  const finish = (callback: () => void) => {
    runtime.lastError = failure ? { message: failure } : undefined;
    callback();
    runtime.lastError = undefined;
  };
  const sync = {
    get: vi.fn((_keys: unknown, callback: (items: Record<string, unknown>) => void) => {
      finish(() => callback(structuredClone(values)));
    }),
    set: vi.fn((updates: Record<string, unknown>, callback: () => void) => {
      if (!failure) Object.assign(values, structuredClone(updates));
      finish(callback);
    }),
    remove: vi.fn((keys: string[], callback: () => void) => {
      if (!failure) for (const key of keys) delete values[key];
      finish(callback);
    })
  };
  vi.stubGlobal('chrome', { runtime, storage: { sync } });
  return { values, sync, fail: (message?: string) => { failure = message; } };
}

afterEach(() => vi.unstubAllGlobals());

describe('Browser Sync storage transport', () => {
  test('reports unavailable browser sync instead of using an unsafe local fallback', async () => {
    vi.stubGlobal('chrome', undefined);
    expect(browserSyncAvailable()).toBe(false);
    await expect(readBrowserSyncItems()).rejects.toMatchObject({ code: 'unavailable' });
    await expect(writeBrowserSyncItems({}, { account: {} })).rejects.toMatchObject({ code: 'unavailable' });
  });

  test('batches writes and skips empty updates', async () => {
    const storage = installSyncStorage({ untouched: 1 });
    await writeBrowserSyncItems(storage.values, {});
    expect(storage.sync.set).not.toHaveBeenCalled();
    await writeBrowserSyncItems(storage.values, { first: { value: 1 }, second: { value: 2 } });
    expect(storage.sync.set).toHaveBeenCalledTimes(1);
    expect(await readBrowserSyncItems()).toEqual({ untouched: 1, first: { value: 1 }, second: { value: 2 } });
  });

  test('counts UTF-8 bytes and rejects oversized items before any partial upload', async () => {
    const storage = installSyncStorage();
    await expect(writeBrowserSyncItems({}, { small: 'okay', large: '界'.repeat(3000) })).rejects.toMatchObject({ code: 'quota' });
    expect(storage.sync.set).not.toHaveBeenCalled();
    expect(storage.values).toEqual({});
  });

  test('accounts for every namespace when enforcing total size and item limits', async () => {
    const storage = installSyncStorage();
    const full = Object.fromEntries(Array.from({ length: 512 }, (_, index) => [`key-${index}`, 'x']));
    await expect(writeBrowserSyncItems(full, { extra: 1 })).rejects.toMatchObject({ code: 'quota' });
    const large = Object.fromEntries(Array.from({ length: 20 }, (_, index) => [`key-${index}`, 'x'.repeat(5100)]));
    await expect(writeBrowserSyncItems(large, { extra: 'x'.repeat(1000) })).rejects.toMatchObject({ code: 'quota' });
    expect(storage.sync.set).not.toHaveBeenCalled();
    await expect(writeBrowserSyncItems(full, { 'key-0': 'replacement' })).resolves.toBeUndefined();
  });

  test.each([
    ['QUOTA_BYTES quota exceeded', 'quota'],
    ['MAX_WRITE_OPERATIONS_PER_MINUTE exceeded', 'quota'],
    ['Storage unavailable', 'storage']
  ])('propagates callback failure %s', async (message, code) => {
    const storage = installSyncStorage();
    storage.fail(message);
    await expect(readBrowserSyncItems()).rejects.toMatchObject({ code });
    await expect(writeBrowserSyncItems({}, { value: 1 })).rejects.toMatchObject({ code });
    expect(storage.values).toEqual({});
  });
});

describe('Browser Sync sessions', () => {
  test('joining a missing group or supplying an invalid key never creates cloud data', async () => {
    const storage = installSyncStorage();
    await expect(connectBrowserSync('password123', true, [])).rejects.toMatchObject({ code: 'invalidKey' });
    await expect(connectBrowserSync(generateSyncRecoveryKey(), true, [])).rejects.toMatchObject({ code: 'notFound' });
    expect(storage.sync.set).not.toHaveBeenCalled();
  });

  test('authenticates the entire group and ignores unknown namespaces', async () => {
    const key = generateSyncRecoveryKey();
    const marker = await createSyncMarker(key);
    const storage = installSyncStorage({ [marker.storageKey]: marker.value, [`${SYNC_PREFIX}unrelated:broken`]: 'invalid' });
    const connected = await connectBrowserSync(key, true, []);
    expect(connected.accounts).toEqual([]);
    const originalState = structuredClone(connected.state);
    storage.values[marker.storageKey] = { ...marker.value, data: 'A'.repeat(24) };
    await expect(prepareBrowserSync(connected.state, connected.accounts)).rejects.toMatchObject({ code: 'invalidData' });
    expect(connected.state).toEqual(originalState);
    expect(storage.sync.set).not.toHaveBeenCalled();
  });

  test('rejects a tampered account without applying any otherwise valid records', async () => {
    const key = generateSyncRecoveryKey();
    const storage = installSyncStorage();
    const connected = await connectBrowserSync(key, false, []);
    const account = createAccount({ label: 'Valid', secret: 'JBSWY3DPEHPK3PXP' });
    const item = await encryptSyncRecord(key, { id: account.id, revision: 1, deviceId: crypto.randomUUID(), account });
    storage.values[item.storageKey] = item.value;
    storage.values[`${SYNC_PREFIX}${await getSyncNamespace(key)}:broken`] = {};
    await expect(prepareBrowserSync(connected.state, connected.accounts)).rejects.toMatchObject({ code: 'invalidData' });
    expect(connected.accounts).toEqual([]);
    expect(connected.state.records).toEqual({});
    expect(storage.sync.set).toHaveBeenCalledTimes(1); // group marker only
  });

  test('publishes each local account once and does not rewrite ciphertext on refresh', async () => {
    const storage = installSyncStorage();
    const account = createAccount({ label: 'Local', secret: 'JBSWY3DPEHPK3PXP' });
    const connected = await connectBrowserSync(generateSyncRecoveryKey(), false, [account]);
    const first = await prepareBrowserSync(connected.state, connected.accounts);
    expect(storage.sync.set).toHaveBeenCalledTimes(1);
    await first.publish();
    expect(storage.sync.set).toHaveBeenCalledTimes(2);
    const before = structuredClone(storage.values);
    const refresh = await prepareBrowserSync(first.state, first.accounts);
    await refresh.publish();
    expect(storage.sync.set).toHaveBeenCalledTimes(2);
    expect(storage.values).toEqual(before);
  });

  test('retries persisted local winners after callback upload failures', async () => {
    const storage = installSyncStorage();
    const account = createAccount({ label: 'Local', secret: 'JBSWY3DPEHPK3PXP' });
    const connected = await connectBrowserSync(generateSyncRecoveryKey(), false, [account]);
    const pending = await prepareBrowserSync(connected.state, connected.accounts);
    storage.fail('Storage unavailable');
    await expect(pending.publish()).rejects.toMatchObject({ code: 'storage' });
    storage.fail();
    const retry = await prepareBrowserSync(pending.state, pending.accounts);
    expect(retry.state).toEqual(pending.state);
    await retry.publish();
    const otherDevice = await connectBrowserSync(connected.state.recoveryKey, true, []);
    expect(otherDevice.accounts[0]).toEqual(account);
  });

  test('merges simultaneous devices without either overwriting the other device account', async () => {
    installSyncStorage();
    const recoveryKey = generateSyncRecoveryKey();
    const first = await connectBrowserSync(recoveryKey, false, []);
    const second = await connectBrowserSync(recoveryKey, true, []);
    expect(first.state.deviceId).not.toBe(second.state.deviceId);
    const a = createAccount({ label: 'First', secret: 'JBSWY3DPEHPK3PXP' });
    const b = createAccount({ label: 'Second', secret: 'JBSWY3DPEHPK3PXP' });
    const aPrepared = await prepareBrowserSync(first.state, [a]);
    const bPrepared = await prepareBrowserSync(second.state, [b]);
    await aPrepared.publish();
    await bPrepared.publish();
    const aMerged = await prepareBrowserSync(aPrepared.state, aPrepared.accounts);
    const bMerged = await prepareBrowserSync(bPrepared.state, bPrepared.accounts);
    expect(new Set(aMerged.accounts.map((account) => account.id))).toEqual(new Set([a.id, b.id]));
    expect(new Set(bMerged.accounts.map((account) => account.id))).toEqual(new Set([a.id, b.id]));
    expect(aMerged.state.records).toEqual(bMerged.state.records);
  });

  test('retains failed deletions and prevents an old device snapshot resurrecting an account', async () => {
    const storage = installSyncStorage();
    const key = generateSyncRecoveryKey();
    const account = createAccount({ label: 'Original', secret: 'JBSWY3DPEHPK3PXP' });
    const first = await connectBrowserSync(key, false, [account]);
    const uploaded = await prepareBrowserSync(first.state, first.accounts);
    await uploaded.publish();
    const other = await connectBrowserSync(key, true, []);
    const deletion = await prepareBrowserSync(uploaded.state, []);
    storage.fail('Storage unavailable');
    await expect(deletion.publish()).rejects.toMatchObject({ code: 'storage' });
    storage.fail();
    const retried = await prepareBrowserSync(deletion.state, deletion.accounts);
    await retried.publish();
    const staleDevice = await prepareBrowserSync(other.state, [{ ...other.accounts[0], label: 'Edited offline' }]);
    expect(staleDevice.accounts).toEqual([]);
    expect(staleDevice.state.records[account.id].account).toBeNull();
  });

  test('deletes only the current group and cancels a previously prepared upload', async () => {
    const storage = installSyncStorage({ unrelated: 'keep' });
    const key = generateSyncRecoveryKey();
    const group = await connectBrowserSync(key, false, []);
    const secondKey = generateSyncRecoveryKey();
    await connectBrowserSync(secondKey, false, []);
    const account = createAccount({ label: 'Pending', secret: 'JBSWY3DPEHPK3PXP' });
    const prepared = await prepareBrowserSync(group.state, [account]);
    await deleteBrowserSyncGroup(key);
    const afterDeletion = structuredClone(storage.values);
    await expect(prepared.publish()).rejects.toMatchObject({ code: 'notFound' });
    expect(storage.values).toEqual(afterDeletion);
    await expect(prepareBrowserSync(prepared.state, prepared.accounts)).rejects.toMatchObject({ code: 'notFound' });
    await expect(connectBrowserSync(secondKey, true, [])).resolves.toMatchObject({ accounts: [] });
    expect(storage.values.unrelated).toBe('keep');
    expect(prepared.accounts).toEqual([account]);
  });

  test('rechecks marker authentication before publishing a prepared account', async () => {
    const storage = installSyncStorage();
    const key = generateSyncRecoveryKey();
    const group = await connectBrowserSync(key, false, []);
    const account = createAccount({ label: 'Pending', secret: 'JBSWY3DPEHPK3PXP' });
    const prepared = await prepareBrowserSync(group.state, [account]);
    const marker = Object.keys(storage.values)[0];
    storage.values[marker] = {};
    await expect(prepared.publish()).rejects.toMatchObject({ code: 'invalidData' });
    expect(storage.sync.set).toHaveBeenCalledTimes(1);
  });

  test('preflights against quota consumed after preparation', async () => {
    const storage = installSyncStorage();
    const group = await connectBrowserSync(generateSyncRecoveryKey(), false, []);
    const account = createAccount({ label: 'Pending', secret: 'JBSWY3DPEHPK3PXP' });
    const prepared = await prepareBrowserSync(group.state, [account]);
    Object.assign(storage.values, Object.fromEntries(Array.from({ length: 511 }, (_, index) => [`other-${index}`, true])));
    await expect(prepared.publish()).rejects.toMatchObject({ code: 'quota' });
    expect(storage.sync.set).toHaveBeenCalledTimes(1);
    expect(prepared.accounts).toEqual([account]);
  });
});
