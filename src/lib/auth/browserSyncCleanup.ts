import { SYNC_PREFIX } from './browserSync';
import { BrowserSyncError, readBrowserSyncItems } from './browserSyncStorage';

const DELETED_GROUP_PREFIX = 'vastblast.2fa-authenticator.deleted-sync-group.';
const NAMESPACE = /^[0-9a-f]{32}$/;

/** Only an explicit deletion creates this durable, non-secret cleanup intent. */
export async function rememberDeletedSyncGroup(namespace: string): Promise<void> {
  if (!NAMESPACE.test(namespace)) throw new BrowserSyncError('invalidData');
  await new Promise<void>((resolve, reject) => {
    chrome.storage.local.set({ [`${DELETED_GROUP_PREFIX}${namespace}`]: true }, () => settle(resolve, reject));
  });
}

export async function isDeletedSyncGroup(namespace: string): Promise<boolean> {
  const key = `${DELETED_GROUP_PREFIX}${namespace}`;
  const items = await readLocalItems(key);
  return items[key] === true;
}

/** Cleanup needs only public namespaces, so it also works with a locked vault. */
export async function cleanupDeletedSyncGroups(): Promise<void> {
  const local = await readLocalItems(null);
  const prefixes = Object.entries(local).flatMap(([key, value]) => {
    const namespace = key.slice(DELETED_GROUP_PREFIX.length);
    return key.startsWith(DELETED_GROUP_PREFIX) && NAMESPACE.test(namespace) && value === true
      ? [`${SYNC_PREFIX}${namespace}:`] : [];
  });
  if (prefixes.length === 0) return;
  const items = await readBrowserSyncItems();
  const keys = Object.keys(items).filter((key) => prefixes.some((prefix) => key.startsWith(prefix)));
  if (keys.length === 0) return;
  await new Promise<void>((resolve, reject) => {
    chrome.storage.sync.remove(keys, () => settle(resolve, reject));
  });
}

/** Start at background initialization to catch delayed writes and retry failures. */
export function installBrowserSyncCleanup(): () => void {
  let pending = Promise.resolve();
  const schedule = () => {
    // Keep the intent on failure; the next arrival or background start retries.
    pending = pending.then(cleanupDeletedSyncGroups).catch(() => undefined);
  };
  const listener = (changes: Record<string, chrome.storage.StorageChange>, area: string) => {
    const relevant = Object.entries(changes).some(([key, change]) =>
      (area === 'sync' && key.startsWith(SYNC_PREFIX) && change.newValue !== undefined) ||
      (area === 'local' && key.startsWith(DELETED_GROUP_PREFIX) && change.newValue === true)
    );
    if (relevant) schedule();
  };
  chrome.storage.onChanged.addListener(listener);
  schedule();
  return () => chrome.storage.onChanged.removeListener(listener);
}

async function readLocalItems(key: string | null): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(key, (items) => settle(() => resolve(items), reject));
  });
}

function settle(resolve: () => void, reject: (error: Error) => void): void {
  if (chrome.runtime.lastError) reject(new BrowserSyncError('storage'));
  else resolve();
}
