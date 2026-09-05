import {
  SYNC_PREFIX,
  alignSyncAccounts,
  createSyncMarker,
  decryptSyncRecord,
  encryptSyncRecord,
  getSyncMarkerKey,
  getSyncNamespace,
  mergeSyncRecords,
  parseSyncRecoveryKey,
  reconcileSyncAccounts,
  validateSyncMarker,
  type BrowserSyncRecord,
  type BrowserSyncState
} from './browserSync';
import { BrowserSyncError, readBrowserSyncItems, writeBrowserSyncItems } from './browserSyncStorage';
import type { AuthenticatorAccount } from './types';

export async function connectBrowserSync(
  input: string,
  join: boolean,
  localAccounts: AuthenticatorAccount[]
): Promise<{ state: BrowserSyncState; accounts: AuthenticatorAccount[] }> {
  let recoveryKey: string;
  try {
    recoveryKey = parseSyncRecoveryKey(input);
  } catch {
    throw new BrowserSyncError('invalidKey');
  }
  const items = await readBrowserSyncItems();
  const markerKey = await getSyncMarkerKey(recoveryKey);
  if (!join && !items[markerKey]) {
    const marker = await createSyncMarker(recoveryKey);
    await writeBrowserSyncItems(items, { [marker.storageKey]: marker.value });
    items[marker.storageKey] = marker.value;
  }
  const records = mergeSyncRecords(await readRecords(recoveryKey, items));
  return {
    state: { recoveryKey, deviceId: crypto.randomUUID(), records: Object.fromEntries(records.map((record) => [record.id, record])) },
    accounts: alignSyncAccounts(localAccounts, records)
  };
}

/** The caller commits state/accounts locally before publishing, making retries durable. */
export async function prepareBrowserSync(state: BrowserSyncState, accounts: AuthenticatorAccount[]) {
  const items = await readBrowserSyncItems();
  const records = await readRecords(state.recoveryKey, items);
  const next = reconcileSyncAccounts(state, accounts, records);
  const updates: Record<string, unknown> = {};
  for (const record of next.writes) {
    // Match the plaintext first to avoid fresh IVs and needless writes on every check.
    if (records.some((remote) => JSON.stringify(remote) === JSON.stringify(record))) continue;
    try {
      const item = await encryptSyncRecord(state.recoveryKey, record);
      updates[item.storageKey] = item.value;
    } catch (error) {
      if (error instanceof Error && /storage limit/.test(error.message)) throw new BrowserSyncError('quota');
      throw error;
    }
  }
  return {
    ...next,
    publish: async () => {
      if (Object.keys(updates).length === 0) return;
      // A local vault write separates preparation from publishing. Check again
      // in case another device removed this group or consumed storage meanwhile.
      const current = await readBrowserSyncItems();
      await readMarker(state.recoveryKey, current);
      await writeBrowserSyncItems(current, updates);
    }
  };
}

export async function deleteBrowserSyncGroup(recoveryKey: string): Promise<void> {
  const items = await readBrowserSyncItems();
  const prefix = `${SYNC_PREFIX}${await getSyncNamespace(recoveryKey)}:`;
  const keys = Object.keys(items).filter((key) => key.startsWith(prefix));
  if (keys.length === 0) return;
  await new Promise<void>((resolve, reject) => {
    chrome.storage.sync.remove(keys, () => {
      if (chrome.runtime.lastError) reject(new BrowserSyncError('storage'));
      else resolve();
    });
  });
}

async function readRecords(recoveryKey: string, items: Record<string, unknown>): Promise<BrowserSyncRecord[]> {
  const markerKey = await readMarker(recoveryKey, items);
  try {
    const prefix = `${SYNC_PREFIX}${await getSyncNamespace(recoveryKey)}:`;
    return await Promise.all(Object.entries(items)
      .filter(([key]) => key.startsWith(prefix) && key !== markerKey)
      .map(([key, value]) => decryptSyncRecord(recoveryKey, key, value)));
  } catch {
    throw new BrowserSyncError('invalidData');
  }
}

async function readMarker(recoveryKey: string, items: Record<string, unknown>): Promise<string> {
  const markerKey = await getSyncMarkerKey(recoveryKey);
  if (!items[markerKey]) throw new BrowserSyncError('notFound');
  try {
    await validateSyncMarker(recoveryKey, items[markerKey]);
    return markerKey;
  } catch {
    throw new BrowserSyncError('invalidData');
  }
}
