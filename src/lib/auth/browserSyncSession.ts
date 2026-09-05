import {
  SYNC_PREFIX,
  alignSyncAccounts,
  createSyncMarker,
  decryptSyncRecord,
  encryptSyncRecord,
  getSyncMarkerKey,
  getSyncNamespace,
  parseSyncRecoveryKey,
  reconcileSyncAccounts,
  validateSyncMarker,
  type BrowserSyncRecord,
  type BrowserSyncState
} from './browserSync';
import { BrowserSyncError, readBrowserSyncItems, writeBrowserSyncItems } from './browserSyncStorage';
import { cleanupDeletedSyncGroups, isDeletedSyncGroup, rememberDeletedSyncGroup } from './browserSyncCleanup';
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
    if (await isDeletedSyncGroup(await getSyncNamespace(recoveryKey))) throw new BrowserSyncError('notFound');
    const marker = await createSyncMarker(recoveryKey);
    await writeBrowserSyncItems(items, { [marker.storageKey]: marker.value });
    items[marker.storageKey] = marker.value;
  }
  const records = await readRecords(recoveryKey, items);
  // Merged counters need a durable local revision before any contributing slot changes.
  const { state } = reconcileSyncAccounts({ recoveryKey, deviceId: crypto.randomUUID(), records: {} }, [], records);
  return {
    state,
    accounts: alignSyncAccounts(localAccounts, Object.values(state.records))
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
  await rememberDeletedSyncGroup(await getSyncNamespace(recoveryKey));
  await cleanupDeletedSyncGroups();
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
  if (await isDeletedSyncGroup(await getSyncNamespace(recoveryKey))) throw new BrowserSyncError('notFound');
  const markerKey = await getSyncMarkerKey(recoveryKey);
  if (!items[markerKey]) throw new BrowserSyncError('notFound');
  try {
    await validateSyncMarker(recoveryKey, items[markerKey]);
    return markerKey;
  } catch {
    throw new BrowserSyncError('invalidData');
  }
}
