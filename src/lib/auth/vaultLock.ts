const VAULT_LOCK = 'vastblast.2fa-authenticator.vault';
let fallbackQueue: Promise<void> = Promise.resolve();

/** Serialize complete read-modify-write operations across extension pages and workers. */
export function withVaultLock<T>(operation: () => Promise<T>): Promise<T> {
  if (typeof navigator !== 'undefined' && navigator.locks) {
    return navigator.locks.request(VAULT_LOCK, operation);
  }

  // Development environments without Web Locks still serialize this module's callers.
  const result = fallbackQueue.then(operation);
  fallbackQueue = result.then(
    () => undefined,
    () => undefined
  );
  return result;
}
