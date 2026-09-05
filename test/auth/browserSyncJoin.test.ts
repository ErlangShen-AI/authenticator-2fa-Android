import { describe, expect, test } from 'vitest';
import {
  createSyncMarker,
  encryptSyncRecord,
  generateSyncRecoveryKey,
  mergeSyncRecords,
  withSyncOrigin,
  type BrowserSyncRecord
} from '../../src/lib/auth/browserSync';
import { connectBrowserSync, prepareBrowserSync } from '../../src/lib/auth/browserSyncSession';
import { createAccount } from '../../src/lib/auth/otp';
import { mergeImportedAccounts } from '../../src/lib/auth/vaultImport';
import { createBrowserSyncNetwork } from '../helpers/browserSync';

const DEVICE_A = '00000000-0000-4000-8000-000000000001';
const DEVICE_B = '00000000-0000-4000-8000-000000000002';

describe('Browser Sync joining', () => {
  test.each([false, true])('a delayed account stays deleted by its joining backup (prepared before deletion: %s)', async (preparedFirst) => {
    const network = createBrowserSyncNetwork();
    network.createDevice().install();
    const recoveryKey = generateSyncRecoveryKey();
    const created = await connectBrowserSync(recoveryKey, false, []);
    const added = await mergeImportedAccounts([], [createAccount({ label: 'Account', secret: 'JBSWY3DPEHPK3PXP' })], created.state);
    const early = preparedFirst ? await prepareBrowserSync(added.browserSync!, added.accounts) : undefined;

    const joined = await connectBrowserSync(recoveryKey, true, added.accounts);
    const uploaded = await prepareBrowserSync(joined.state, joined.accounts);
    await uploaded.publish();
    const deleted = await prepareBrowserSync(uploaded.state, []);
    await deleted.publish();
    const delayed = early ?? await prepareBrowserSync(added.browserSync!, added.accounts);
    if (!preparedFirst) expect(delayed.accounts).toEqual([]);
    await delayed.publish();

    const delivered = await prepareBrowserSync(deleted.state, []);
    await delivered.publish();
    expect(delivered.accounts).toEqual([]);
    expect((await connectBrowserSync(recoveryKey, true, [])).accounts).toEqual([]);
    const records = [...Object.values(delayed.state.records), ...Object.values(deleted.state.records)];
    const merged = mergeSyncRecords(records);
    expect(mergeSyncRecords([...records].reverse())).toEqual(merged);
    expect(mergeSyncRecords([...merged, ...records])).toEqual(merged);
  });

  test.each([false, true])('a restored account protects its generation before first upload (old deletion has origins: %s)', async (hasOrigins) => {
    const network = createBrowserSyncNetwork();
    network.createDevice().install();
    const recoveryKey = generateSyncRecoveryKey();
    const original = createAccount({ label: 'Account', secret: 'JBSWY3DPEHPK3PXP' });
    const created = await connectBrowserSync(recoveryKey, false, []);
    const imported = await mergeImportedAccounts([], [original], created.state);
    const old = await withSyncOrigin({ id: original.id, revision: 1, deviceId: DEVICE_A, account: original });
    await seedRecords(network.cloud, recoveryKey, [old]);

    const restored = await prepareBrowserSync(imported.browserSync!, imported.accounts);
    await restored.publish();
    await seedRecords(network.cloud, recoveryKey, [{
      id: old.id, revision: 2, deviceId: old.deviceId, account: null,
      ...(hasOrigins ? { origins: old.origins } : {})
    }]);
    const retained = await prepareBrowserSync(restored.state, restored.accounts);
    expect(retained.accounts).toEqual(restored.accounts);
    const deleted = await prepareBrowserSync(retained.state, []);
    await deleted.publish();

    expect((await connectBrowserSync(recoveryKey, true, restored.accounts)).accounts).toEqual([]);
  });

  test('preserves independently changed credentials when their shared backup ID arrives after joining', async () => {
    const network = createBrowserSyncNetwork();
    network.createDevice().install();
    const recoveryKey = generateSyncRecoveryKey();
    const original = createAccount({ label: 'Account', secret: 'JBSWY3DPEHPK3PXP' });
    const local = { ...original, secret: 'KRUGS4ZANFZSAYJA' };
    await seedGroup(network.cloud, recoveryKey, []);

    const joined = await connectBrowserSync(recoveryKey, true, [local]);
    const initial = await prepareBrowserSync(joined.state, joined.accounts);
    await initial.publish();
    await seedRecords(network.cloud, recoveryKey, [{ id: original.id, revision: 2, deviceId: DEVICE_A, account: original }]);

    const delivered = await prepareBrowserSync(initial.state, initial.accounts);
    await delivered.publish();
    expect(delivered.accounts.map((account) => account.secret).sort()).toEqual([original.secret, local.secret].sort());
    expect(new Set(delivered.accounts.map((account) => account.id)).size).toBe(2);

    network.createDevice().install();
    const nextDevice = await connectBrowserSync(recoveryKey, true, []);
    expect(nextDevice.accounts.map((account) => account.secret).sort()).toEqual([original.secret, local.secret].sort());
    const deleted = await prepareBrowserSync(nextDevice.state, nextDevice.accounts.filter((account) => account.secret === original.secret));
    await deleted.publish();
    expect((await connectBrowserSync(recoveryKey, true, [])).accounts.map((account) => account.secret)).toEqual([original.secret]);
  });

  test('keeps a joining copy deleted when its original record arrives only after deletion', async () => {
    const network = createBrowserSyncNetwork();
    network.createDevice().install();
    const recoveryKey = generateSyncRecoveryKey();
    const original = createAccount({ label: 'Account', secret: 'JBSWY3DPEHPK3PXP', type: 'hotp', counter: 1 });
    await seedGroup(network.cloud, recoveryKey, []);
    const joined = await connectBrowserSync(recoveryKey, true, [original]);
    const initial = await prepareBrowserSync(joined.state, joined.accounts);
    await initial.publish();
    const deleted = await prepareBrowserSync(initial.state, []);
    await deleted.publish();

    await seedRecords(network.cloud, recoveryKey, [{
      id: original.id, revision: 3, deviceId: DEVICE_A,
      account: { ...original, label: 'Renamed elsewhere', counter: 20 }
    }]);
    const delivered = await prepareBrowserSync(deleted.state, []);
    await delivered.publish();
    expect(delivered.accounts).toEqual([]);

    network.createDevice().install();
    expect((await connectBrowserSync(recoveryKey, true, [])).accounts).toEqual([]);
  });

  test('changing a live account to a deleted independent credential does not delete the live identity', async () => {
    const network = createBrowserSyncNetwork();
    network.createDevice().install();
    const recoveryKey = generateSyncRecoveryKey();
    const original = createAccount({ label: 'Account', secret: 'JBSWY3DPEHPK3PXP' });
    const changed = { ...original, secret: 'KRUGS4ZANFZSAYJA' };
    const created = await connectBrowserSync(recoveryKey, false, [original]);
    const initial = await prepareBrowserSync(created.state, created.accounts);
    await initial.publish();

    const joined = await connectBrowserSync(recoveryKey, true, [changed]);
    const uploaded = await prepareBrowserSync(joined.state, joined.accounts);
    await uploaded.publish();
    const deleted = await prepareBrowserSync(uploaded.state, uploaded.accounts.filter((account) => account.secret === original.secret));
    await deleted.publish();

    const edited = await prepareBrowserSync(initial.state, initial.accounts.map((account) => ({ ...account, secret: changed.secret })));
    await edited.publish();
    const nextDevice = await connectBrowserSync(recoveryKey, true, []);
    expect(nextDevice.accounts).toEqual([expect.objectContaining({ secret: changed.secret })]);
    const removed = await prepareBrowserSync(nextDevice.state, []);
    await removed.publish();
    expect((await connectBrowserSync(recoveryKey, true, nextDevice.accounts)).accounts).toEqual([]);
  });

  test('merges matching encrypted records delivered after the joining device publishes its copy', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    device.install();
    const recoveryKey = generateSyncRecoveryKey();
    const original = { ...createAccount({ label: 'Account', secret: 'JBSWY3DPEHPK3PXP' }), id: 'a-original' };
    const local = { ...original, id: 'b-local', sortOrder: 6 };
    await seedGroup(network.cloud, recoveryKey, []);
    const joined = await connectBrowserSync(recoveryKey, true, [local]);
    const initial = await prepareBrowserSync(joined.state, joined.accounts);
    await initial.publish();

    await seedRecords(network.cloud, recoveryKey, [{ id: original.id, revision: 1, deviceId: DEVICE_A, account: original }]);
    const delivered = await prepareBrowserSync(initial.state, initial.accounts);
    await delivered.publish();

    expect(delivered.accounts).toEqual([{ ...original, id: expect.any(String), sortOrder: 6 }]);
    expect(delivered.writes).toEqual([
      expect.objectContaining({ id: delivered.accounts[0].id, deviceId: joined.state.deviceId })
    ]);
    expect((await connectBrowserSync(recoveryKey, true, [])).accounts).toEqual([{ ...original, id: delivered.accounts[0].id }]);
    const repeated = await prepareBrowserSync(delivered.state, delivered.accounts);
    const writes = device.sync.writes;
    expect(repeated.state).toEqual(delivered.state);
    await repeated.publish();
    expect(device.sync.writes).toBe(writes);
  });

  test('retries a merged counter durably before its contributing remote slot is replaced', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    device.install();
    const recoveryKey = generateSyncRecoveryKey();
    const account = createAccount({ label: 'Counter', secret: 'JBSWY3DPEHPK3PXP', type: 'hotp', counter: 100 });
    const high: BrowserSyncRecord = { id: account.id, revision: 1, deviceId: DEVICE_A, account };
    const newer: BrowserSyncRecord = {
      ...high, revision: 2, deviceId: DEVICE_B, account: { ...account, label: 'Renamed', counter: 1 }
    };
    await seedGroup(network.cloud, recoveryKey, [high, newer]);

    const joined = await connectBrowserSync(recoveryKey, true, []);
    expect(joined.accounts[0]).toMatchObject({ label: 'Renamed', counter: 100 });
    const prepared = await prepareBrowserSync(joined.state, joined.accounts);
    device.sync.writeError = 'Offline';
    await expect(prepared.publish()).rejects.toMatchObject({ code: 'storage' });
    device.sync.writeError = '';
    const retried = await prepareBrowserSync(prepared.state, prepared.accounts);
    expect(retried.state).toEqual(prepared.state);
    expect(retried.writes).toEqual(prepared.writes);
    await retried.publish();

    // One device replaces its secret while an offline device later edits the old account.
    await seedRecords(network.cloud, recoveryKey, [
      { ...high, revision: 3, account: { ...account, secret: 'KRUGS4ZANFZSAYJA', counter: 1 } },
      { ...newer, revision: 4, account: { ...newer.account!, label: 'Edited offline' } }
    ]);

    const nextDevice = await connectBrowserSync(recoveryKey, true, []);
    expect(nextDevice.accounts[0]).toMatchObject({ label: 'Edited offline', secret: account.secret, counter: 100 });
    expect(prepared.writes).toEqual([
      expect.objectContaining({ deviceId: joined.state.deviceId, revision: 3, account: expect.objectContaining({ counter: 100 }) })
    ]);
  });

  test('publishes a larger local counter and keeps the joining identity deleted', async () => {
    const network = createBrowserSyncNetwork();
    network.createDevice().install();
    const recoveryKey = generateSyncRecoveryKey();
    const account = createAccount({ label: 'Counter', secret: 'JBSWY3DPEHPK3PXP', type: 'hotp', counter: 1 });
    const local = { ...account, id: crypto.randomUUID(), counter: 100 };
    await seedGroup(network.cloud, recoveryKey, [{ id: account.id, revision: 1, deviceId: DEVICE_A, account }]);

    const joined = await connectBrowserSync(recoveryKey, true, [local]);
    const prepared = await prepareBrowserSync(joined.state, joined.accounts);
    await prepared.publish();

    expect((await connectBrowserSync(recoveryKey, true, [])).accounts).toEqual([
      expect.objectContaining({ id: prepared.accounts[0].id, counter: 100 })
    ]);

    const deleted = await prepareBrowserSync(prepared.state, []);
    await deleted.publish();
    await seedRecords(network.cloud, recoveryKey, [{ id: local.id, revision: 1, deviceId: DEVICE_B, account: local }]);

    expect((await connectBrowserSync(recoveryKey, true, [])).accounts).toEqual([]);
  });

  test('does not republish a counter already present in the winning remote record', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    device.install();
    const recoveryKey = generateSyncRecoveryKey();
    const account = createAccount({ label: 'Counter', secret: 'JBSWY3DPEHPK3PXP', type: 'hotp', counter: 100 });
    await seedGroup(network.cloud, recoveryKey, [
      { id: account.id, revision: 1, deviceId: DEVICE_A, account: { ...account, counter: 1 } },
      { id: account.id, revision: 2, deviceId: DEVICE_B, account }
    ]);

    const joined = await connectBrowserSync(recoveryKey, true, []);
    const prepared = await prepareBrowserSync(joined.state, joined.accounts);
    await prepared.publish();

    expect(prepared.writes).toEqual([]);
    expect(device.sync.writes).toBe(0);
  });
});

async function seedGroup(cloud: Record<string, unknown>, recoveryKey: string, records: BrowserSyncRecord[]): Promise<void> {
  const marker = await createSyncMarker(recoveryKey);
  cloud[marker.storageKey] = marker.value;
  await seedRecords(cloud, recoveryKey, records);
}

async function seedRecords(cloud: Record<string, unknown>, recoveryKey: string, records: BrowserSyncRecord[]): Promise<void> {
  for (const record of records) {
    const item = await encryptSyncRecord(recoveryKey, record);
    cloud[item.storageKey] = item.value;
  }
}
