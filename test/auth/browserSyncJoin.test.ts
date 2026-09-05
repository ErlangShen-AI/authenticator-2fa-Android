import { describe, expect, test } from 'vitest';
import {
  createSyncMarker,
  encryptSyncRecord,
  generateSyncRecoveryKey,
  type BrowserSyncRecord
} from '../../src/lib/auth/browserSync';
import { connectBrowserSync, prepareBrowserSync } from '../../src/lib/auth/browserSyncSession';
import { createAccount } from '../../src/lib/auth/otp';
import { createBrowserSyncNetwork } from '../helpers/browserSync';

const DEVICE_A = '00000000-0000-4000-8000-000000000001';
const DEVICE_B = '00000000-0000-4000-8000-000000000002';

describe('Browser Sync joining', () => {
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

    expect(delivered.accounts).toEqual([{ ...original, sortOrder: 6 }]);
    expect(delivered.writes).toEqual([
      expect.objectContaining({ id: original.id, deviceId: joined.state.deviceId, mergedIds: [local.id] })
    ]);
    expect((await connectBrowserSync(recoveryKey, true, [])).accounts).toEqual([original]);
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

  test('publishes a larger local counter while keeping the remote identity', async () => {
    const network = createBrowserSyncNetwork();
    network.createDevice().install();
    const recoveryKey = generateSyncRecoveryKey();
    const account = createAccount({ label: 'Counter', secret: 'JBSWY3DPEHPK3PXP', type: 'hotp', counter: 1 });
    await seedGroup(network.cloud, recoveryKey, [{ id: account.id, revision: 1, deviceId: DEVICE_A, account }]);

    const joined = await connectBrowserSync(recoveryKey, true, [{ ...account, id: crypto.randomUUID(), counter: 100 }]);
    const prepared = await prepareBrowserSync(joined.state, joined.accounts);
    await prepared.publish();

    expect((await connectBrowserSync(recoveryKey, true, [])).accounts).toEqual([
      expect.objectContaining({ id: account.id, counter: 100 })
    ]);
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
