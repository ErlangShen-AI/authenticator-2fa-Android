import { beforeEach, describe, expect, test } from 'vitest';
import { loadStoredVault, saveStoredVault, saveVaultSessionKey } from '../../src/lib/auth/storage';
import { generateSyncRecoveryKey } from '../../src/lib/auth/browserSync';
import { createAccount } from '../../src/lib/auth/otp';
import { createDefaultAppSettings } from '../../src/lib/auth/types';
import {
  createVaultEnvelope,
  exportVaultKey,
  getVaultKeyFingerprint,
  unlockVaultEnvelope
} from '../../src/lib/auth/vaultCrypto';
import { importTextIntoStoredVault } from '../../src/lib/auth/vaultImport';
import { isEncryptedVaultRecord, isPlainVaultRecord } from '../../src/lib/auth/vaultRecords';
import { AuthenticatorVault } from '../../src/lib/state/authenticator.svelte';
import { installMemoryStorage, installStructuredCloneChromeStorage } from '../helpers/storage';

const ALICE_URI = otpAuthUri('alice@example.com');
const BOB_URI = otpAuthUri('bob@example.com');
const PASSWORD = 'correct horse battery staple';

describe('importTextIntoStoredVault', () => {
  beforeEach(() => {
    installMemoryStorage();
  });

  test('imports into an empty plain vault', async () => {
    Object.defineProperty(globalThis, 'chrome', {
      configurable: true,
      value: { i18n: { getUILanguage: () => 'pt-BR' } }
    });

    const result = await importTextIntoStoredVault(ALICE_URI);

    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(0);

    const stored = await loadStoredVault();
    if (!isPlainVaultRecord(stored)) {
      throw new Error('Expected a plain vault record.');
    }
    expect(stored.data.accounts).toHaveLength(1);
    expect(stored.data.accounts[0].label).toBe('alice@example.com');
    expect(stored.data.accounts[0].sortOrder).toBe(0);
    expect(stored.data.settings.language).toBe('pt');
    expect(stored.data.settings.accountSortMode).toBe('contextual');
  });

  test('preserves both accounts when background imports overlap', async () => {
    installStructuredCloneChromeStorage({ localWriteDelayMs: 10 });

    const results = await Promise.all([
      importTextIntoStoredVault(ALICE_URI),
      importTextIntoStoredVault(BOB_URI)
    ]);

    expect(results.map((result) => result.imported)).toEqual([1, 1]);
    const stored = await loadStoredVault();
    if (!isPlainVaultRecord(stored)) {
      throw new Error('Expected a plain vault record.');
    }
    expect(stored.data.accounts.map((account) => account.label)).toEqual([
      'alice@example.com',
      'bob@example.com'
    ]);
  });

  test('preserves a manual sorting preference when importing into a plain vault', async () => {
    const vault = new AuthenticatorVault();
    await vault.initialize();
    await vault.updateSettings({ accountSortMode: 'manual' });

    await importTextIntoStoredVault(ALICE_URI);

    const reopened = new AuthenticatorVault();
    await reopened.initialize();
    expect(reopened.settings.accountSortMode).toBe('manual');
  });

  test('rejects malformed JSON account imports before storage', async () => {
    const malformed = JSON.stringify({
      accounts: [
        {
          id: 'bad-account',
          label: 'Broken',
          secret: 'A'
        }
      ]
    });

    await expect(importTextIntoStoredVault(malformed)).rejects.toThrow('Imported account is not valid.');
    expect(await loadStoredVault()).toBeNull();
  });

  test('reports duplicates without resetting an HOTP counter or account order', async () => {
    const hotpUri = ALICE_URI.replace('/totp/', '/hotp/');
    await importTextIntoStoredVault(`${hotpUri}&counter=100`);

    const duplicate = await importTextIntoStoredVault(`${hotpUri}&counter=1`);

    expect(duplicate.imported).toBe(0);
    expect(duplicate.skipped).toBe(1);

    const stored = await loadStoredVault();
    if (!isPlainVaultRecord(stored)) {
      throw new Error('Expected a plain vault record.');
    }
    expect(stored.data.accounts).toHaveLength(1);
    expect(stored.data.accounts[0].sortOrder).toBe(0);
    expect(stored.data.accounts[0].counter).toBe(100);
  });

  test('preserves different OTP parameters while skipping exact duplicates', async () => {
    await importTextIntoStoredVault(ALICE_URI);
    const variants = ['algorithm=SHA256', 'digits=8', 'period=60'].map((query) => `${ALICE_URI}&${query}`);
    const result = await importTextIntoStoredVault([ALICE_URI, ...variants, variants[0]].join('\n'));

    expect(result.imported).toBe(3);
    expect(result.skipped).toBe(2);

    const stored = await loadStoredVault();
    if (!isPlainVaultRecord(stored)) {
      throw new Error('Expected a plain vault record.');
    }
    expect(stored.data.accounts.map(({ algorithm, digits, period }) => [algorithm, digits, period])).toEqual([
      ['SHA-1', 6, 30],
      ['SHA-256', 6, 30],
      ['SHA-1', 8, 30],
      ['SHA-1', 6, 60]
    ]);
  });

  test('regenerates imported account IDs that collide with existing accounts', async () => {
    await importTextIntoStoredVault(ALICE_URI);

    const storedBefore = await loadStoredVault();
    if (!isPlainVaultRecord(storedBefore)) {
      throw new Error('Expected a plain vault record.');
    }

    const result = await importTextIntoStoredVault(
      JSON.stringify({
        accounts: [
          {
            ...storedBefore.data.accounts[0],
            label: 'alice.backup@example.com'
          }
        ]
      })
    );

    expect(result.imported).toBe(1);

    const storedAfter = await loadStoredVault();
    if (!isPlainVaultRecord(storedAfter)) {
      throw new Error('Expected a plain vault record.');
    }
    expect(storedAfter.data.accounts).toHaveLength(2);
    expect(new Set(storedAfter.data.accounts.map((account) => account.id)).size).toBe(2);
  });

  test('imports into an encrypted vault while the session key is available', async () => {
    const { sessionStorage } = installMemoryStorage();
    const vault = new AuthenticatorVault();
    await vault.initialize();
    await vault.importText(ALICE_URI);
    await vault.updateSettings({ accountSortMode: 'contextual' });
    await vault.changePassword('', PASSWORD);
    sessionStorage.setItem = () => {
      throw new Error('session failed');
    };

    const result = await importTextIntoStoredVault(BOB_URI);

    expect(result.imported).toBe(1);

    const reopened = new AuthenticatorVault();
    await reopened.initialize();
    expect(reopened.locked).toBe(false);
    expect(reopened.passwordProtected).toBe(true);
    expect(reopened.settings.accountSortMode).toBe('contextual');
    expect(reopened.sortedAccounts.map((account) => account.label)).toEqual([
      'alice@example.com',
      'bob@example.com'
    ]);
  });

  test('preserves encrypted Browser Sync credentials and revisions during a background import', async () => {
    installStructuredCloneChromeStorage();
    const account = createAccount({
      issuer: 'Example',
      label: 'alice@example.com',
      secret: 'JBSWY3DPEHPK3PXP'
    });
    const deviceId = crypto.randomUUID();
    const browserSync = {
      recoveryKey: generateSyncRecoveryKey(),
      deviceId,
      records: {
        [account.id]: { id: account.id, deviceId, revision: 3, account }
      }
    };
    const { envelope, key } = await createVaultEnvelope({
      accounts: [account],
      settings: createDefaultAppSettings(),
      browserSync
    }, PASSWORD);
    await saveStoredVault(envelope);
    await saveVaultSessionKey(getVaultKeyFingerprint(envelope), await exportVaultKey(key));

    const result = await importTextIntoStoredVault(BOB_URI);

    expect(result.imported).toBe(1);
    const stored = await loadStoredVault();
    if (!isEncryptedVaultRecord(stored)) {
      throw new Error('Expected an encrypted vault record.');
    }
    expect(JSON.stringify(stored)).not.toContain(browserSync.recoveryKey);
    const { data } = await unlockVaultEnvelope(stored, PASSWORD);
    expect(data.browserSync).toMatchObject({ recoveryKey: browserSync.recoveryKey, deviceId });
    expect(data.browserSync?.records[account.id]).toMatchObject({ revision: 3, deviceId });
    expect(data.accounts.map((item) => item.label)).toEqual([
      'alice@example.com',
      'bob@example.com'
    ]);
  });

  test('a background JSON import of a deleted synced account gets a fresh ID', async () => {
    installStructuredCloneChromeStorage();
    const account = createAccount({ label: 'Alice', secret: 'JBSWY3DPEHPK3PXP' });
    const deviceId = crypto.randomUUID();
    const browserSync = {
      recoveryKey: generateSyncRecoveryKey(),
      deviceId,
      records: { [account.id]: { id: account.id, deviceId, revision: 3, account: null } }
    };
    const { envelope, key } = await createVaultEnvelope({
      accounts: [],
      settings: createDefaultAppSettings(),
      browserSync
    }, PASSWORD);
    await saveStoredVault(envelope);
    await saveVaultSessionKey(getVaultKeyFingerprint(envelope), await exportVaultKey(key));

    const result = await importTextIntoStoredVault(JSON.stringify({ accounts: [account] }));

    expect(result.imported).toBe(1);
    const stored = await loadStoredVault();
    if (!isEncryptedVaultRecord(stored)) throw new Error('Expected an encrypted vault record.');
    const { data } = await unlockVaultEnvelope(stored, PASSWORD);
    expect(data.accounts[0].id).not.toBe(account.id);
    expect(data.accounts[0].label).toBe('Alice');
    expect(data.browserSync).toMatchObject(browserSync);
    expect(data.browserSync?.records[data.accounts[0].id].restorationId).toBe(data.accounts[0].id);
  });

  test('rejects encrypted imports after the vault is manually locked', async () => {
    const vault = new AuthenticatorVault();
    await vault.initialize();
    await vault.importText(ALICE_URI);
    await vault.changePassword('', PASSWORD);
    await vault.lock();

    await expect(importTextIntoStoredVault(BOB_URI)).rejects.toThrow(
      'Unlock the vault before importing the scanned QR code.'
    );
  });
});

function otpAuthUri(label: string): string {
  return `otpauth://totp/${encodeURIComponent(`Example:${label}`)}?secret=JBSWY3DPEHPK3PXP&issuer=Example`;
}
