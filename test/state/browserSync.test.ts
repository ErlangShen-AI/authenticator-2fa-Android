import { describe, expect, test } from 'vitest';
import { generateSyncRecoveryKey, type BrowserSyncEnvelope } from '../../src/lib/auth/browserSync';
import { createEncryptedBackupFile } from '../../src/lib/auth/backup';
import { loadStoredVault } from '../../src/lib/auth/storage';
import { unlockVaultEnvelope } from '../../src/lib/auth/vaultCrypto';
import { isEncryptedVaultRecord } from '../../src/lib/auth/vaultRecords';
import { AuthenticatorVault } from '../../src/lib/state/authenticator.svelte';
import { importTextIntoStoredVault } from '../../src/lib/auth/vaultImport';
import { createBrowserSyncNetwork, type BrowserSyncDevice } from '../helpers/browserSync';

const PASSWORD = 'correct horse battery staple';
const OTHER_PASSWORD = 'another device private password';
const SECRET = 'JBSWY3DPEHPK3PXP';

describe('Browser Sync vault integration', () => {
  test('joins two protected devices, preserves both account lists and keeps preferences local', async () => {
    const network = createBrowserSyncNetwork();
    const firstDevice = network.createDevice();
    const first = await createProtectedVault(firstDevice, ['Alice']);
    await first.updateSettings({ theme: 'dark', hideCodes: true });
    const recoveryKey = generateSyncRecoveryKey();
    await first.startBrowserSync(recoveryKey, false);
    expect(first.syncStatus).toBe('ready');

    const secondDevice = network.createDevice();
    const second = await createProtectedVault(secondDevice, ['Bob'], OTHER_PASSWORD);
    await second.updateSettings({ language: 'fr', theme: 'light' });
    await second.startBrowserSync(recoveryKey, true);
    expect(labels(second)).toEqual(['Alice', 'Bob']);
    expect(second.settings.theme).toBe('light');
    expect(second.settings.language).toBe('fr');
    expect(second.settings.hideCodes).toBe(false);

    firstDevice.install();
    await first.syncNow();
    expect(labels(first)).toEqual(['Alice', 'Bob']);
    expect(first.settings.theme).toBe('dark');
    expect(first.settings.hideCodes).toBe(true);
  });

  test('preserves independently edited backup credentials with the same ID when joining', async () => {
    const network = createBrowserSyncNetwork();
    const firstDevice = network.createDevice();
    const first = await createProtectedVault(firstDevice, ['Alice']);
    const backup = JSON.stringify({ accounts: first.accounts });
    const originalId = first.accounts[0].id;
    const secondDevice = network.createDevice();
    const second = await createProtectedVault(secondDevice);
    await second.importText(backup);
    expect(second.accounts[0].id).toBe(originalId);
    const replacementSecret = 'KRUGS4ZANFZSAYJA';
    await second.updateAccount(originalId, { secret: replacementSecret });

    firstDevice.install();
    const recoveryKey = generateSyncRecoveryKey();
    await first.startBrowserSync(recoveryKey, false);
    secondDevice.install();
    await second.startBrowserSync(recoveryKey, true);

    expect(second.syncStatus).toBe('ready');
    expect(second.accounts.map((account) => account.secret).sort()).toEqual([SECRET, replacementSecret].sort());
    expect(new Set(second.accounts.map((account) => account.id)).size).toBe(2);
    const third = await createProtectedVault(network.createDevice());
    await third.startBrowserSync(recoveryKey, true);
    expect(third.accounts.map((account) => account.secret).sort()).toEqual([SECRET, replacementSecret].sort());

    await third.deleteAccount(third.accounts.find((account) => account.secret === replacementSecret)!.id);
    await third.syncNow();
    firstDevice.install();
    await first.syncNow();
    expect(first.accounts).toEqual([expect.objectContaining({ id: originalId, secret: SECRET })]);
  });

  test('keeps secrets and the recovery key out of sync storage and the local vault envelope', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Private account label']);
    const recoveryKey = generateSyncRecoveryKey();
    await vault.startBrowserSync(recoveryKey, false);

    for (const stored of [network.cloud, device.local.values]) {
      const json = JSON.stringify(stored);
      expect(json).not.toContain(SECRET);
      expect(json).not.toContain(recoveryKey);
      expect(json).not.toContain('Private account label');
    }
    expect(Object.keys(network.cloud).length).toBeGreaterThan(1);
    const stored = await loadStoredVault();
    if (!isEncryptedVaultRecord(stored)) throw new Error('Expected encrypted vault.');
    const { data } = await unlockVaultEnvelope(stored, PASSWORD);
    expect(data.browserSync?.recoveryKey).toBe(recoveryKey);
  });

  test('requires password protection before creating a remote group', async () => {
    const network = createBrowserSyncNetwork();
    network.createDevice().install();
    const vault = new AuthenticatorVault();
    await vault.initialize();
    await vault.addAccount({ label: 'Local account', secret: SECRET });

    await vault.startBrowserSync(generateSyncRecoveryKey(), false);

    expect(vault.syncEnabled).toBe(false);
    expect(vault.syncError).toBe('passwordRequired');
    expect(labels(vault)).toEqual(['Local account']);
    expect(network.cloud).toEqual({});
  });

  test.each([
    ['invalid key', 'invalidKey'],
    [generateSyncRecoveryKey(), 'notFound']
  ])('a failed join leaves local accounts and encrypted storage intact: %s', async (key, error) => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Local account']);
    const before = structuredClone(device.local.values);

    await vault.startBrowserSync(key, true);

    expect(vault.syncEnabled).toBe(false);
    expect(vault.syncError).toBe(error);
    expect(labels(vault)).toEqual(['Local account']);
    expect(device.local.values).toEqual(before);
    expect(network.cloud).toEqual({});
  });

  test('rejects tampered remote ciphertext before changing local accounts', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Alice']);
    await vault.startBrowserSync(generateSyncRecoveryKey(), false);
    const before = structuredClone(device.local.values);
    const recordKey = Object.keys(network.cloud).find((key) => !key.endsWith(':marker'))!;
    const envelope = network.cloud[recordKey] as BrowserSyncEnvelope;
    envelope.data = (envelope.data[0] === 'A' ? 'B' : 'A') + envelope.data.slice(1);

    await vault.syncNow();

    expect(vault.syncError).toBe('invalidData');
    expect(vault.syncStatus).toBe('pending');
    expect(labels(vault)).toEqual(['Alice']);
    expect(device.local.values).toEqual(before);
  });

  test('merges offline edits and additions without restoring a deleted account', async () => {
    const network = createBrowserSyncNetwork();
    const firstDevice = network.createDevice();
    const first = await createProtectedVault(firstDevice, ['Alice', 'Bob']);
    const recoveryKey = generateSyncRecoveryKey();
    await first.startBrowserSync(recoveryKey, false);
    const secondDevice = network.createDevice();
    const second = await createProtectedVault(secondDevice);
    await second.startBrowserSync(recoveryKey, true);
    const alice = second.accounts.find((account) => account.label === 'Alice')!;
    const bob = second.accounts.find((account) => account.label === 'Bob')!;

    firstDevice.install();
    firstDevice.sync.readError = 'Sync is offline';
    await first.deleteAccount(alice.id);
    await first.addAccount({ label: 'Carol', secret: SECRET });
    await first.syncNow();
    expect(first.syncStatus).toBe('pending');

    secondDevice.install();
    secondDevice.sync.readError = 'Sync is offline';
    await second.updateAccount(alice.id, { label: 'Alice renamed offline' });
    await second.updateAccount(bob.id, { label: 'Bob updated' });
    await second.syncNow();
    expect(second.syncStatus).toBe('pending');
    secondDevice.sync.readError = '';
    await second.syncNow();

    firstDevice.install();
    firstDevice.sync.readError = '';
    await first.syncNow();
    expect(labels(first)).toEqual(['Bob updated', 'Carol']);

    secondDevice.install();
    await second.syncNow();
    expect(labels(second)).toEqual(['Bob updated', 'Carol']);
  });

  test.each(['json', 'encrypted'] as const)('explicit %s backup imports can restore an account deleted from sync', async (format) => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Alice']);
    const account = vault.accounts[0];
    const backup = format === 'json'
      ? JSON.stringify({ accounts: [account] })
      : await (await createEncryptedBackupFile([account], vault.settings, PASSWORD)).blob.text();
    const recoveryKey = generateSyncRecoveryKey();
    await vault.startBrowserSync(recoveryKey, false);
    await vault.deleteAccount(account.id);
    await vault.syncNow();
    expect(vault.accounts).toEqual([]);

    const imported = format === 'json'
      ? await vault.importText(backup)
      : await vault.importEncryptedBackupText(backup, PASSWORD);
    await vault.syncNow();

    expect(imported.imported).toBe(1);
    expect(labels(vault)).toEqual(['Alice']);
    expect(vault.accounts[0].id).not.toBe(account.id);
    const second = await createProtectedVault(network.createDevice());
    await second.startBrowserSync(recoveryKey, true);
    expect(labels(second)).toEqual(['Alice']);
    expect(second.accounts[0].id).toBe(vault.accounts[0].id);
  });

  test('explicitly restoring a backup before a pending deletion syncs still creates a new identity', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Alice']);
    const account = vault.accounts[0];
    const recoveryKey = generateSyncRecoveryKey();
    await vault.startBrowserSync(recoveryKey, false);
    const remoteBefore = structuredClone(network.cloud);

    await vault.deleteAccount(account.id);
    expect(network.cloud).toEqual(remoteBefore);
    await vault.importText(JSON.stringify({ accounts: [account] }));
    expect(vault.accounts[0].id).not.toBe(account.id);
    await vault.syncNow();

    const second = await createProtectedVault(network.createDevice());
    await second.startBrowserSync(recoveryKey, true);
    expect(labels(second)).toEqual(['Alice']);
    expect(second.accounts[0].id).toBe(vault.accounts[0].id);
  });

  describe.each(['tombstone', 'live account then tombstone'])('delayed %s delivery', (delivery) => {
    test.each(['json', 'encrypted', 'background'] as const)('preserves an explicit %s restore', async (format) => {
      const network = createBrowserSyncNetwork();
      const firstDevice = network.createDevice();
      const first = await createProtectedVault(firstDevice);
      const recoveryKey = generateSyncRecoveryKey();
      await first.startBrowserSync(recoveryKey, false);
      const secondDevice = network.createDevice();
      const second = await createProtectedVault(secondDevice);
      await second.startBrowserSync(recoveryKey, true);

      firstDevice.install();
      await first.addAccount({ label: 'Restored account', secret: SECRET });
      await first.syncNow();
      const account = first.accounts[0];
      const backup = format === 'encrypted'
        ? await (await createEncryptedBackupFile([account], first.settings, PASSWORD)).blob.text()
        : JSON.stringify({ accounts: [account] });
      const live = structuredClone(network.cloud);
      await first.deleteAccount(account.id);
      await first.syncNow();
      const deleted = structuredClone(network.cloud);
      if (delivery === 'live account then tombstone') Object.assign(network.cloud, live);

      secondDevice.install();
      const result = format === 'background'
        ? await importTextIntoStoredVault(backup)
        : format === 'encrypted'
          ? await second.importEncryptedBackupText(backup, PASSWORD)
          : await second.importText(backup);
      expect(result.imported).toBe(1);
      if (format === 'background') await second.initialize();
      await second.syncNow();
      if (delivery === 'live account then tombstone') {
        Object.assign(network.cloud, deleted);
        await second.syncNow();
      }

      expect(labels(second)).toEqual(['Restored account']);
      expect(second.accounts[0].id).not.toBe(account.id);
    });
  });

  test('a local password change preserves the sync key and other device passwords', async () => {
    const network = createBrowserSyncNetwork();
    const firstDevice = network.createDevice();
    const first = await createProtectedVault(firstDevice, ['Alice']);
    const recoveryKey = generateSyncRecoveryKey();
    await first.startBrowserSync(recoveryKey, false);
    const secondDevice = network.createDevice();
    const second = await createProtectedVault(secondDevice, [], OTHER_PASSWORD);
    await second.startBrowserSync(recoveryKey, true);

    firstDevice.install();
    await first.changePassword(PASSWORD, 'new local password');
    expect(first.error).toBe('');
    expect(first.syncRecoveryKey).toBe(recoveryKey);
    await first.lock();
    expect(first.syncRecoveryKey).toBe('');
    await first.unlock('new local password');
    expect(first.syncRecoveryKey).toBe(recoveryKey);

    secondDevice.install();
    await second.lock();
    await second.unlock(OTHER_PASSWORD);
    expect(second.locked).toBe(false);
    expect(second.syncRecoveryKey).toBe(recoveryKey);
  });

  test('keeps the greatest HOTP counter through concurrent metadata edits and subsequent joins', async () => {
    const network = createBrowserSyncNetwork();
    const firstDevice = network.createDevice();
    const first = await createProtectedVault(firstDevice);
    await first.addAccount({ label: 'Counter account', secret: SECRET, type: 'hotp', counter: 4 });
    const recoveryKey = generateSyncRecoveryKey();
    await first.startBrowserSync(recoveryKey, false);
    const accountId = first.accounts[0].id;
    const secondDevice = network.createDevice();
    const second = await createProtectedVault(secondDevice);
    await second.startBrowserSync(recoveryKey, true);

    firstDevice.install();
    firstDevice.sync.readError = 'Offline';
    for (let count = 0; count < 3; count++) await first.advanceHotp(accountId);
    await first.syncNow();
    expect(first.accounts[0].counter).toBe(7);

    secondDevice.install();
    await second.updateAccount(accountId, { label: 'Renamed counter account' });
    await second.syncNow();

    firstDevice.install();
    firstDevice.sync.readError = '';
    await first.syncNow();
    expect(first.accounts[0].counter).toBe(7);
    secondDevice.install();
    await second.syncNow();
    expect(second.accounts[0].counter).toBe(7);
    await second.advanceHotp(accountId);
    await second.syncNow();

    const third = await createProtectedVault(network.createDevice());
    await third.startBrowserSync(recoveryKey, true);
    expect(third.accounts[0].counter).toBe(8);
  });

  test('repeated sync checks and local account reordering do not consume sync writes', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Alice', 'Bob']);
    await vault.startBrowserSync(generateSyncRecoveryKey(), false);
    const writes = device.sync.writes;

    await vault.syncNow();
    await vault.syncNow();
    await vault.updateSettings({ accountSortMode: 'manual' });
    await vault.reorderAccounts(vault.sortedAccounts.map((account) => account.id).reverse());
    await vault.syncNow();

    expect(vault.sortedAccounts.map((account) => account.label)).toEqual(['Bob', 'Alice']);
    expect(device.sync.writes).toBe(writes);
    expect(vault.syncStatus).toBe('ready');
  });

  test.each([false, true])('rejects removing password protection with sync enabled (locked: %s)', async (locked) => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Alice']);
    const recoveryKey = generateSyncRecoveryKey();
    await vault.startBrowserSync(recoveryKey, false);
    if (locked) await vault.lock();

    await vault.removePassword(PASSWORD);

    expect(vault.passwordProtected).toBe(true);
    expect(vault.error).toContain('Browser Sync');
    expect(isEncryptedVaultRecord(await loadStoredVault())).toBe(true);
    expect(JSON.stringify(device.local.values)).not.toContain(recoveryKey);
  });

  test.each(['stop', 'reset'] as const)('%s keeps the remote group recoverable', async (action) => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Alice']);
    const recoveryKey = generateSyncRecoveryKey();
    await vault.startBrowserSync(recoveryKey, false);
    const remoteBefore = structuredClone(network.cloud);

    if (action === 'stop') await vault.stopBrowserSync();
    else await vault.resetVault();

    expect(vault.syncEnabled).toBe(false);
    expect(network.cloud).toEqual(remoteBefore);
    if (action === 'stop') {
      expect(labels(vault)).toEqual(['Alice']);
      await vault.removePassword(PASSWORD);
      expect(vault.passwordProtected).toBe(false);
      expect(JSON.stringify(device.local.values)).not.toContain(recoveryKey);
    }
    const second = await createProtectedVault(network.createDevice());
    await second.startBrowserSync(recoveryKey, true);
    expect(labels(second)).toEqual(['Alice']);
  });

  test.each([
    ['MAX_WRITE_OPERATIONS_PER_MINUTE quota exceeded', 'quota'],
    ['Storage write failed', 'storage']
  ])('retries durable pending data after reopening when upload fails: %s', async (message, code) => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Alice']);
    const recoveryKey = generateSyncRecoveryKey();
    await vault.startBrowserSync(recoveryKey, false);
    device.sync.writeError = message;
    await vault.addAccount({ label: 'Pending account', secret: SECRET });
    await vault.syncNow();
    expect(vault.syncStatus).toBe('pending');
    expect(vault.syncError).toBe(code);
    expect(labels(vault)).toEqual(['Alice', 'Pending account']);

    device.sync.writeError = '';
    const reopened = new AuthenticatorVault();
    await reopened.initialize();
    expect(reopened.syncStatus).toBe('ready');
    expect(labels(reopened)).toEqual(['Alice', 'Pending account']);

    const second = await createProtectedVault(network.createDevice());
    await second.startBrowserSync(recoveryKey, true);
    expect(labels(second)).toEqual(['Alice', 'Pending account']);
  });

  test('retains a pending addition when the total sync quota is full', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Alice']);
    const recoveryKey = generateSyncRecoveryKey();
    await vault.startBrowserSync(recoveryKey, false);
    for (let index = 0; index < 14; index++) network.cloud[`unrelated:${index}`] = 'x'.repeat(7000);
    const usedBytes = Object.entries(network.cloud).reduce((total, [key, value]) =>
      total + new TextEncoder().encode(key + JSON.stringify(value)).byteLength, 0);
    const paddingKey = 'unrelated:padding';
    network.cloud[paddingKey] = 'x'.repeat(102400 - usedBytes - paddingKey.length - 2 - 128);
    await vault.addAccount({ label: 'Pending account', secret: SECRET });
    await vault.syncNow();
    expect(vault.syncError).toBe('quota');
    expect(labels(vault)).toEqual(['Alice', 'Pending account']);

    for (const key of Object.keys(network.cloud)) {
      if (key.startsWith('unrelated:')) delete network.cloud[key];
    }
    await vault.syncNow();
    expect(vault.syncStatus).toBe('ready');
    const second = await createProtectedVault(network.createDevice());
    await second.startBrowserSync(recoveryKey, true);
    expect(labels(second)).toEqual(['Alice', 'Pending account']);
  });

  test('failed local persistence does not publish or claim an added account', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const vault = await createProtectedVault(device, ['Alice']);
    await vault.startBrowserSync(generateSyncRecoveryKey(), false);
    const remoteBefore = structuredClone(network.cloud);
    const localBefore = structuredClone(device.local.values);
    device.local.writeError = 'Local storage failed';

    await expect(vault.addAccount({ label: 'Unsaved account', secret: SECRET })).rejects.toThrow('Local storage failed');

    expect(labels(vault)).toEqual(['Alice']);
    expect(network.cloud).toEqual(remoteBefore);
    expect(device.local.values).toEqual(localBefore);
  });

  test('serializes stale vault instances so overlapping imports and settings updates survive', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const first = await createProtectedVault(device, ['Alice']);
    await first.startBrowserSync(generateSyncRecoveryKey(), false);
    const second = new AuthenticatorVault();
    await second.initialize();
    device.local.writeDelayMs = 5;

    await Promise.all([
      first.addAccount({ label: 'Bob', secret: SECRET }),
      second.addAccount({ label: 'Carol', secret: SECRET }),
      first.updateSettings({ hideCodes: true }),
      second.updateSettings({ theme: 'dark' })
    ]);

    const reopened = new AuthenticatorVault();
    await reopened.initialize();
    expect(labels(reopened)).toEqual(['Alice', 'Bob', 'Carol']);
    expect(reopened.settings.hideCodes).toBe(true);
    expect(reopened.settings.theme).toBe('dark');
  });

  test('a stale unlocked instance cannot mutate the vault after another instance locks it', async () => {
    const network = createBrowserSyncNetwork();
    const device = network.createDevice();
    const first = await createProtectedVault(device, ['Alice']);
    await first.startBrowserSync(generateSyncRecoveryKey(), false);
    const second = new AuthenticatorVault();
    await second.initialize();
    const before = structuredClone(device.local.values);

    await first.lock();
    await expect(second.addAccount({ label: 'Blocked account', secret: SECRET })).rejects.toThrow('Unlock');

    expect(second.locked).toBe(true);
    expect(second.accounts).toEqual([]);
    expect(second.syncRecoveryKey).toBe('');
    expect(device.local.values).toEqual(before);
  });

  test('explicitly deleting a remote group leaves local accounts and prevents another device recreating it', async () => {
    const network = createBrowserSyncNetwork();
    const firstDevice = network.createDevice();
    const first = await createProtectedVault(firstDevice, ['Alice']);
    const recoveryKey = generateSyncRecoveryKey();
    await first.startBrowserSync(recoveryKey, false);
    const secondDevice = network.createDevice();
    const second = await createProtectedVault(secondDevice);
    await second.startBrowserSync(recoveryKey, true);

    firstDevice.install();
    await first.deleteBrowserSync();
    expect(first.syncEnabled).toBe(false);
    expect(labels(first)).toEqual(['Alice']);
    expect(network.cloud).toEqual({});

    secondDevice.install();
    await second.syncNow();
    expect(second.syncError).toBe('notFound');
    expect(labels(second)).toEqual(['Alice']);
    expect(network.cloud).toEqual({});
  });
});

async function createProtectedVault(device: BrowserSyncDevice, accountLabels: string[] = [], password = PASSWORD) {
  device.install();
  const vault = new AuthenticatorVault();
  await vault.initialize();
  for (const label of accountLabels) await vault.addAccount({ label, secret: SECRET });
  await vault.changePassword('', password);
  expect(vault.error).toBe('');
  return vault;
}

function labels(vault: AuthenticatorVault): string[] {
  return vault.accounts.map((account) => account.label).sort();
}
