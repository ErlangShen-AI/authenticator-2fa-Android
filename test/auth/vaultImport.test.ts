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
import { importTextIntoStoredVault, mergeImportedAccounts } from '../../src/lib/auth/vaultImport';
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

  test('reports duplicates without rewriting account order', async () => {
    await importTextIntoStoredVault(ALICE_URI);

    const duplicate = await importTextIntoStoredVault(ALICE_URI);

    expect(duplicate.imported).toBe(0);
    expect(duplicate.skipped).toBe(1);

    const stored = await loadStoredVault();
    if (!isPlainVaultRecord(stored)) {
      throw new Error('Expected a plain vault record.');
    }
    expect(stored.data.accounts).toHaveLength(1);
    expect(stored.data.accounts[0].sortOrder).toBe(0);
  });

  test('skips duplicate accounts within the same import batch', async () => {
    const result = await importTextIntoStoredVault([ALICE_URI, ALICE_URI].join('\n'));

    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(1);

    const stored = await loadStoredVault();
    if (!isPlainVaultRecord(stored)) {
      throw new Error('Expected a plain vault record.');
    }
    expect(stored.data.accounts).toHaveLength(1);
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
    expect(data.browserSync).toEqual(browserSync);
    expect(data.accounts.map((item) => item.label)).toEqual([
      'alice@example.com',
      'bob@example.com'
    ]);
  });

  test('assigns an explicitly imported account a new ID when its previous ID is reserved', () => {
    const account = createAccount({ label: 'Alice', secret: 'JBSWY3DPEHPK3PXP' });

    const imported = mergeImportedAccounts([], [account], [account.id]);

    expect(imported.imported).toBe(1);
    expect(imported.accounts[0]).toMatchObject({ label: account.label, secret: account.secret });
    expect(imported.accounts[0].id).not.toBe(account.id);
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
    expect(data.browserSync).toEqual(browserSync);
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
