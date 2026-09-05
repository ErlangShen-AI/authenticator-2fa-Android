export class MemoryStorage implements Storage {
  private values = new Map<string, string>();

  get length(): number {
    return this.values.size;
  }

  clear(): void {
    this.values.clear();
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  key(index: number): string | null {
    return Array.from(this.values.keys())[index] ?? null;
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

export function installMemoryStorage(): { localStorage: MemoryStorage; sessionStorage: MemoryStorage } {
  const localStorage = new MemoryStorage();
  const sessionStorage = new MemoryStorage();

  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: localStorage
  });
  Object.defineProperty(globalThis, 'sessionStorage', {
    configurable: true,
    value: sessionStorage
  });
  Object.defineProperty(globalThis, 'chrome', {
    configurable: true,
    value: undefined
  });

  return { localStorage, sessionStorage };
}

export function installStructuredCloneChromeStorage(
  { localWriteDelayMs = 0 }: { localWriteDelayMs?: number } = {}
): void {
  type ChangeListener = (changes: Record<string, chrome.storage.StorageChange>, area: string) => void;
  const listeners = new Set<ChangeListener>();
  const notify = (area: string) => (changes: Record<string, chrome.storage.StorageChange>) => {
    for (const listener of listeners) listener(changes, area);
  };
  const local = createChromeStorageArea(notify('local'), localWriteDelayMs);
  const session = createChromeStorageArea(notify('session'));

  Object.defineProperty(globalThis, 'chrome', {
    configurable: true,
    value: {
      runtime: {
        lastError: undefined
      },
      storage: {
        local,
        session,
        onChanged: {
          addListener: (listener: ChangeListener) => listeners.add(listener),
          removeListener: (listener: ChangeListener) => listeners.delete(listener)
        }
      }
    }
  });
}

function createChromeStorageArea(
  notify: (changes: Record<string, chrome.storage.StorageChange>) => void,
  writeDelayMs = 0
) {
  const values = new Map<string, unknown>();

  return {
    get(key: string, callback: (items: Record<string, unknown>) => void): void {
      callback({ [key]: values.get(key) });
    },
    set(items: Record<string, unknown>, callback: () => void): void {
      // Firefox extension storage structured-clones values and rejects proxies.
      const cloned = structuredClone(items) as Record<string, unknown>;
      const commit = () => {
        const changes: Record<string, chrome.storage.StorageChange> = {};
        for (const [key, value] of Object.entries(cloned)) {
          changes[key] = { oldValue: values.get(key), newValue: value };
          values.set(key, value);
        }
        callback();
        notify(changes);
      };
      if (writeDelayMs > 0) {
        setTimeout(commit, writeDelayMs);
      } else {
        commit();
      }
    },
    remove(key: string, callback: () => void): void {
      const oldValue = values.get(key);
      values.delete(key);
      callback();
      if (oldValue !== undefined) notify({ [key]: { oldValue } });
    }
  };
}
