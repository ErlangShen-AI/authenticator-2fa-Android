import type {} from 'svelte';
import type { BrowserSyncState } from '../auth/browserSync';
import { SYNC_PREFIX } from '../auth/browserSync';
import { connectBrowserSync, deleteBrowserSyncGroup, prepareBrowserSync } from '../auth/browserSyncSession';
import { BrowserSyncError, browserSyncAvailable, type BrowserSyncErrorCode } from '../auth/browserSyncStorage';
import { withVaultLock } from '../auth/vaultLock';
import { createAccount, generateOtpCode, updateAccount } from '../auth/otp';
import {
  clearStoredVault,
  clearVaultSessionKey,
  loadStoredVault,
  loadVaultSessionKey,
  saveStoredVault,
  saveVaultSessionKey
} from '../auth/storage';
import {
  createVaultEnvelope,
  encryptVaultData,
  exportVaultKey,
  getVaultKeyFingerprint,
  importVaultKey,
  unlockVaultEnvelope,
  unlockVaultEnvelopeWithKey
} from '../auth/vaultCrypto';
import { createPlainVaultRecord, isEncryptedVaultRecord, isPlainVaultRecord } from '../auth/vaultRecords';
import { importEncryptedBackup } from '../auth/backup';
import { importAnyText } from '../auth/importText';
import {
  compareAccountOrder,
  mergeImportedAccounts,
  normalizeAccountOrder,
  reorderAccountsById
} from '../auth/vaultImport';
import type {
  AccountDraft,
  AppSettings,
  AuthenticatorAccount,
  ImportResult,
  OtpCode,
  PlainVaultRecord,
  StoredVault,
  VaultData,
  VaultEnvelope
} from '../auth/types';
import { createDefaultAppSettings, normalizeAppSettings } from '../auth/types';

export class AuthenticatorVault {
  initialized = $state(false);
  hasVault = $state(false);
  locked = $state(false);
  passwordProtected = $state(false);
  busy = $state(false);
  accounts = $state.raw<AuthenticatorAccount[]>([]);
  settings = $state.raw<AppSettings>(createDefaultAppSettings());
  codes = $state<Record<string, OtpCode>>({});
  notice = $state('');
  noticeKey = $state(0);
  error = $state('');
  syncStatus = $state<'off' | 'syncing' | 'ready' | 'pending' | 'error'>('off');
  syncError = $state<BrowserSyncErrorCode | ''>('');
  private browserSync = $state.raw<BrowserSyncState | undefined>();
  private storedSnapshot = 'null';
  private nextSyncAttempt = 0;

  syncEnabled = $derived(Boolean(this.browserSync));

  get syncAvailable(): boolean { return browserSyncAvailable(); }
  get syncRecoveryKey(): string { return this.browserSync?.recoveryKey ?? ''; }

  private key: CryptoKey | null = null;
  private encryptedVault: VaultEnvelope | null = null;
  private plainVault: PlainVaultRecord | null = null;
  private mutationQueue: Promise<void> = Promise.resolve();
  private codeRefreshRequest = 0;

  sortedAccounts = $derived.by(() => [...this.accounts].sort(compareAccountOrder));

  async initialize(): Promise<void> {
    await this.enqueueMutation(() => this.initializeNow());
  }

  private async initializeNow(): Promise<void> {
    this.busy = true;
    try {
      const stored = await loadStoredVault();
      await this.applyStoredVault(stored);
      if (!this.locked) {
        await this.refreshCodes();
      }
    } finally {
      this.initialized = true;
      this.busy = false;
    }
  }

  async create(password: string): Promise<void> {
    await this.changePassword('', password);
  }

  async unlock(password: string): Promise<void> {
    await this.enqueueMutation(() => this.unlockNow(password));
  }

  private async unlockNow(password: string): Promise<void> {
    if (!this.encryptedVault) {
      await this.initializeNow();
    }
    if (!this.encryptedVault) {
      this.error = 'No encrypted vault exists yet.';
      return;
    }
    if (!this.locked) {
      return;
    }

    this.busy = true;
    this.clearStatus();
    try {
      const unlocked = await unlockVaultEnvelope(this.encryptedVault, password);
      this.key = unlocked.key;
      this.applyUnlockedData(unlocked.data);
      this.locked = false;
      await this.saveSessionKey(unlocked.key, this.encryptedVault);
      await this.refreshCodes();
    } catch {
      this.error = 'Unlock failed. Check the password and try again.';
    } finally {
      this.busy = false;
    }
  }

  async lock(): Promise<void> {
    await this.enqueueMutation(async () => {
      if (!this.passwordProtected) {
        this.showNotice('Password protection is off.');
        return;
      }

      await clearVaultSessionKey();
      this.key = null;
      this.browserSync = undefined;
      this.syncStatus = 'off';
      this.accounts = [];
      this.codes = {};
      this.locked = true;
      this.showNotice('Vault locked.');
    });
  }

  async addAccount(draft: AccountDraft): Promise<void> {
    const account = createAccount(draft);
    await this.enqueueMutation(() => this.mergeAccounts([account]));
  }

  async updateAccount(id: string, draft: Partial<AccountDraft>): Promise<void> {
    const update = { ...draft };
    await this.enqueueMutation(() => this.updateAccountNow(id, update));
  }

  async deleteAccount(id: string): Promise<void> {
    await this.enqueueMutation(async () => {
      const accounts = this.accounts.filter((account) => account.id !== id);
      await this.persistData({ accounts, settings: this.settings }, 'Account removed.');
      await this.refreshCodes();
    });
  }

  async reorderAccounts(orderedIds: string[]): Promise<void> {
    const requestedOrder = [...orderedIds];
    await this.enqueueMutation(async () => {
      if (this.settings.accountSortMode !== 'manual') {
        return;
      }

      const accounts = reorderAccountsById(this.sortedAccounts, requestedOrder);
      if (!accounts) {
        return;
      }

      await this.persistData({ accounts, settings: this.settings });
    });
  }

  async advanceHotp(id: string): Promise<void> {
    await this.enqueueMutation(async () => {
      const account = this.accounts.find((item) => item.id === id);
      if (!account || account.type !== 'hotp') {
        return;
      }
      await this.updateAccountNow(id, { counter: account.counter + 1 });
    });
  }

  async importText(text: string): Promise<ImportResult> {
    const result = importAnyText(text);
    const merged = await this.enqueueMutation(() => this.mergeAccounts(result.accounts));
    return {
      ...result,
      imported: merged.imported,
      skipped: result.skipped + merged.skipped
    };
  }

  async importEncryptedBackupText(text: string, password: string): Promise<ImportResult> {
    const result = await importEncryptedBackup(text, password);
    const merged = await this.enqueueMutation(() => this.mergeAccounts(result.accounts));
    return {
      ...result,
      imported: merged.imported,
      skipped: result.skipped + merged.skipped
    };
  }

  async updateSettings(settings: Partial<AppSettings>): Promise<void> {
    const update = { ...settings };
    await this.enqueueMutation(() =>
      this.persistData(
        {
          accounts: this.accounts,
          settings: { ...this.settings, ...update }
        },
        'Settings saved.'
      )
    );
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.enqueueMutation(() => this.changePasswordNow(currentPassword, newPassword));
  }

  private async changePasswordNow(currentPassword: string, newPassword: string): Promise<void> {
    this.busy = true;
    this.clearStatus();
    try {
      const wasPasswordProtected = this.passwordProtected;
      let data = this.getCurrentData();
      if (this.passwordProtected) {
        if (!this.encryptedVault) {
          throw new Error('No encrypted vault exists yet.');
        }
        try {
          const unlocked = await unlockVaultEnvelope(this.encryptedVault, currentPassword);
          data = normalizeVaultData(unlocked.data);
        } catch {
          throw new Error('Current password is incorrect.');
        }
      }

      const unlocked = await createVaultEnvelope(data, newPassword);
      await this.saveLocalVault(unlocked.envelope);
      this.key = unlocked.key;
      this.encryptedVault = unlocked.envelope;
      this.plainVault = null;
      this.hasVault = true;
      this.passwordProtected = true;
      this.locked = false;
      this.applyUnlockedData(unlocked.data);
      await this.saveSessionKey(unlocked.key, unlocked.envelope);
      this.showNotice(wasPasswordProtected ? 'Vault password changed.' : 'Vault password set.');
    } catch (error) {
      this.error = getErrorMessage(error);
    } finally {
      this.busy = false;
    }
  }

  async removePassword(currentPassword: string): Promise<void> {
    await this.enqueueMutation(() => this.removePasswordNow(currentPassword));
  }

  private async removePasswordNow(currentPassword: string): Promise<void> {
    if (this.syncEnabled) {
      this.error = 'Turn off Browser Sync before removing password protection.';
      return;
    }
    if (!this.passwordProtected) {
      this.showNotice('Password protection is already off.');
      return;
    }
    if (!this.encryptedVault) {
      this.error = 'No encrypted vault exists yet.';
      return;
    }

    this.busy = true;
    this.clearStatus();
    try {
      let data: VaultData;
      try {
        const unlocked = await unlockVaultEnvelope(this.encryptedVault, currentPassword);
        data = normalizeVaultData(unlocked.data);
      } catch {
        throw new Error('Current password is incorrect.');
      }

      if (data.browserSync) {
        throw new Error('Turn off Browser Sync before removing password protection.');
      }

      const plainVault = createPlainVaultRecord(data, this.plainVault);
      await this.saveLocalVault(plainVault);
      this.key = null;
      this.encryptedVault = null;
      this.plainVault = plainVault;
      this.hasVault = true;
      this.passwordProtected = false;
      this.locked = false;
      this.applyUnlockedData(plainVault.data);
      await clearVaultSessionKey();
      this.showNotice('Vault password removed.');
    } catch (error) {
      this.error = getErrorMessage(error);
    } finally {
      this.busy = false;
    }
  }

  async resetVault(): Promise<void> {
    await this.enqueueMutation(() => this.resetVaultNow());
  }

  private async resetVaultNow(): Promise<void> {
    this.busy = true;
    this.clearStatus();
    try {
      await clearStoredVault();
      this.storedSnapshot = 'null';
      this.browserSync = undefined;
      this.syncStatus = 'off';
      this.syncError = '';
      await clearVaultSessionKey();
      this.key = null;
      this.encryptedVault = null;
      this.plainVault = null;
      this.accounts = [];
      this.codes = {};
      this.settings = createDefaultAppSettings();
      this.hasVault = false;
      this.passwordProtected = false;
      this.locked = false;
    } catch (error) {
      this.error = getErrorMessage(error);
    } finally {
      this.busy = false;
    }
  }

  async refreshCodes(now = Date.now()): Promise<void> {
    const request = ++this.codeRefreshRequest;
    const accounts = this.accounts;
    if (this.locked || accounts.length === 0) {
      this.codes = {};
      return;
    }

    const entries = await Promise.all(accounts.map((account) => generateOtpCode(account, now)));
    if (request !== this.codeRefreshRequest || this.locked || this.accounts !== accounts) {
      return;
    }
    this.codes = Object.fromEntries(entries.map((entry) => [entry.accountId, entry]));
  }

  showNotice(message: string): void {
    this.notice = message;
    this.noticeKey += 1;
  }

  clearNotice(): void {
    this.notice = '';
  }

  private async applyStoredVault(stored: StoredVault | null): Promise<void> {
    this.storedSnapshot = JSON.stringify(stored);
    this.browserSync = undefined;
    this.syncStatus = 'off';
    this.syncError = '';
    this.key = null;
    this.encryptedVault = null;
    this.plainVault = null;
    this.accounts = [];
    this.codes = {};
    this.settings = createDefaultAppSettings();
    this.hasVault = Boolean(stored);
    this.passwordProtected = false;
    this.locked = false;

    if (!stored) {
      return;
    }

    if (isPlainVaultRecord(stored)) {
      this.plainVault = stored;
      this.applyUnlockedData(stored.data);
      return;
    }

    if (!isEncryptedVaultRecord(stored)) {
      this.hasVault = false;
      return;
    }

    this.encryptedVault = stored;
    this.passwordProtected = true;
    this.locked = true;

    const sessionKey = await loadVaultSessionKey(getVaultKeyFingerprint(stored));
    if (!sessionKey) {
      return;
    }

    try {
      const key = await importVaultKey(sessionKey);
      const unlocked = await unlockVaultEnvelopeWithKey(stored, key);
      this.key = unlocked.key;
      this.applyUnlockedData(unlocked.data);
      this.locked = false;
    } catch {
      await clearVaultSessionKey();
    }
  }

  private enqueueMutation<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.mutationQueue.then(() => withVaultLock(async () => {
      // Other extension pages and background imports share this lock. Re-read
      // inside it so a stale popup cannot overwrite their committed changes.
      if (this.initialized) {
        const stored = await loadStoredVault();
        const sessionCleared = this.encryptedVault && !this.locked &&
          !await loadVaultSessionKey(getVaultKeyFingerprint(this.encryptedVault));
        if (JSON.stringify(stored) !== this.storedSnapshot || sessionCleared) {
          await this.applyStoredVault(stored);
          await this.refreshCodes();
        }
      }
      const value = await operation();
      if (this.browserSync && !this.locked && Date.now() >= this.nextSyncAttempt) {
        await this.syncBrowserNow();
      }
      return value;
    }));
    this.mutationQueue = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  private async updateAccountNow(id: string, draft: Partial<AccountDraft>): Promise<void> {
    const index = this.accounts.findIndex((account) => account.id === id);
    if (index === -1) {
      return;
    }

    const accounts = [...this.accounts];
    accounts[index] = updateAccount(accounts[index], draft);
    await this.persistData({ accounts, settings: this.settings }, 'Account updated.');
    await this.refreshCodes();
  }

  private async mergeAccounts(incoming: AuthenticatorAccount[]): Promise<{ imported: number; skipped: number }> {
    if (incoming.length === 0) {
      this.showNotice('No accounts were found to import.');
      return { imported: 0, skipped: 0 };
    }

    const merged = mergeImportedAccounts(
      this.accounts,
      incoming,
      Object.keys(this.browserSync?.records ?? {})
    );
    if (merged.imported === 0) {
      this.showNotice('No new accounts were imported.');
      return { imported: 0, skipped: merged.skipped };
    }

    await this.persistData(
      { accounts: merged.accounts, settings: this.settings },
      `${merged.imported} account${merged.imported === 1 ? '' : 's'} imported.`
    );
    await this.refreshCodes();
    return { imported: merged.imported, skipped: merged.skipped };
  }

  private async persistData(data: VaultData, message?: string, browserSync = this.browserSync): Promise<void> {
    const normalizedData = normalizeVaultData({ ...data, browserSync });

    if (this.passwordProtected) {
      if (!this.key || !this.encryptedVault) {
        throw new Error('Unlock the vault before making changes.');
      }

      const envelope = await encryptVaultData(normalizedData, this.key, this.encryptedVault);
      await this.saveLocalVault(envelope);
      this.encryptedVault = envelope;
      this.plainVault = null;
    } else {
      const plainVault = createPlainVaultRecord(normalizedData, this.plainVault);
      await this.saveLocalVault(plainVault);
      this.plainVault = plainVault;
      this.encryptedVault = null;
      this.key = null;
    }

    this.applyUnlockedData(normalizedData);
    this.hasVault = true;
    this.locked = false;
    if (message) {
      this.showNotice(message);
    }
  }

  async startBrowserSync(recoveryKey: string, join: boolean): Promise<void> {
    await this.runSyncAction(async () => {
      if (this.browserSync) return;
      if (!this.passwordProtected || this.locked) throw new BrowserSyncError('passwordRequired');
      const connected = await connectBrowserSync(recoveryKey, join, this.accounts);
      await this.persistData({ accounts: connected.accounts, settings: this.settings }, undefined, connected.state);
      this.nextSyncAttempt = 0;
      await this.refreshCodes();
    });
  }

  async syncNow(): Promise<void> {
    await this.runSyncAction(async () => { this.nextSyncAttempt = 0; });
  }

  async stopBrowserSync(): Promise<void> {
    await this.runSyncAction(() => this.disconnectBrowserSync());
  }

  async deleteBrowserSync(): Promise<void> {
    await this.runSyncAction(async () => {
      if (!this.browserSync || this.locked) return;
      await deleteBrowserSyncGroup(this.browserSync.recoveryKey);
      await this.disconnectBrowserSync();
    });
  }

  private async disconnectBrowserSync(): Promise<void> {
    if (!this.browserSync || this.locked) return;
    // Explicit null-like override: omit metadata while retaining every local account.
    const previous = this.browserSync;
    this.browserSync = undefined;
    try {
      await this.persistData(this.getCurrentData());
    } catch (error) {
      this.browserSync = previous;
      throw error;
    }
    this.syncStatus = 'off';
    this.syncError = '';
  }

  private async runSyncAction(operation: () => Promise<void>): Promise<void> {
    try {
      await this.enqueueMutation(async () => {
        this.syncError = '';
        this.syncStatus = 'syncing';
        await operation();
        if (!this.browserSync) this.syncStatus = 'off';
      });
    } catch (error) {
      this.reportSyncError(error);
    }
  }

  private async syncBrowserNow(): Promise<void> {
    if (!this.browserSync || this.locked || !this.passwordProtected) return;
    this.syncStatus = 'syncing';
    this.nextSyncAttempt = Date.now() + 5000;
    try {
      const prepared = await prepareBrowserSync(this.browserSync, this.accounts);
      const data = { accounts: prepared.accounts, settings: this.settings, browserSync: prepared.state };
      if (JSON.stringify(normalizeVaultData(data)) !== JSON.stringify(this.getCurrentData())) {
        await this.persistData(data, undefined, prepared.state);
        await this.refreshCodes();
      }
      // If the popup closes here, the encrypted baseline above retains pending
      // records. Opening/unlocking the vault retries without losing changes.
      await prepared.publish();
      this.syncStatus = 'ready';
      this.syncError = '';
    } catch (error) {
      this.reportSyncError(error);
    }
  }

  private reportSyncError(error: unknown): void {
    this.syncError = error instanceof BrowserSyncError ? error.code : 'storage';
    this.syncStatus = this.browserSync ? 'pending' : 'error';
  }

  /** Watch only while an extension page is mounted; no keys live in a worker. */
  watchStorage(): () => void {
    if (typeof chrome === 'undefined' || !chrome.storage?.onChanged) return () => {};
    let timer: ReturnType<typeof setTimeout> | undefined;
    const listener = (changes: Record<string, chrome.storage.StorageChange>, area: string) => {
      const syncChanged = area === 'sync' && Object.keys(changes).some((key) => key.startsWith(SYNC_PREFIX));
      const localChanged = area === 'local' && Boolean(changes['vastblast.2fa-authenticator.vault']);
      const lockedElsewhere = area === 'session' && Boolean(changes['vastblast.2fa-authenticator.session-key']?.oldValue) && !changes['vastblast.2fa-authenticator.session-key'].newValue;
      if (lockedElsewhere) {
        void this.initialize().catch(() => { this.error = 'Unable to reload the vault.'; });
      } else if (localChanged || (syncChanged && this.syncEnabled)) {
        clearTimeout(timer);
        timer = setTimeout(() => {
          void this.syncNow();
        }, 1000);
      }
    };
    chrome.storage.onChanged.addListener(listener);
    const retry = setInterval(() => {
      if (this.syncEnabled && !this.locked) void this.syncNow();
    }, 15000);
    return () => {
      clearTimeout(timer);
      clearInterval(retry);
      chrome.storage.onChanged.removeListener(listener);
    };
  }

  private async saveLocalVault(record: StoredVault): Promise<void> {
    await saveStoredVault(record);
    this.storedSnapshot = JSON.stringify(record);
  }

  private async saveSessionKey(key: CryptoKey, envelope: VaultEnvelope): Promise<void> {
    await saveVaultSessionKey(getVaultKeyFingerprint(envelope), await exportVaultKey(key));
  }

  private applyUnlockedData(data: VaultData): void {
    this.accounts = normalizeAccountOrder(data.accounts);
    this.settings = normalizeAppSettings(data.settings);
    this.browserSync = this.passwordProtected ? data.browserSync : undefined;
    if (this.browserSync) this.syncStatus = 'pending';
  }

  private getCurrentData(): VaultData {
    return normalizeVaultData({
      accounts: this.accounts,
      settings: this.settings,
      browserSync: this.browserSync
    });
  }

  private clearStatus(): void {
    this.clearNotice();
    this.error = '';
  }
}

function normalizeVaultData(data: VaultData): VaultData {
  // Browser extension storage structured-clones values, so persist plain objects
  // instead of Svelte state proxies.
  return {
    accounts: normalizeAccountOrder(data.accounts),
    settings: normalizeAppSettings(data.settings),
    ...(data.browserSync ? { browserSync: JSON.parse(JSON.stringify(data.browserSync)) as BrowserSyncState } : {})
  };
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

export const authenticatorVault = new AuthenticatorVault();
