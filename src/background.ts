import type { PageContext } from './lib/auth/accountRanking';
import { installBrowserSyncCleanup } from './lib/auth/browserSyncCleanup';

installBrowserSyncCleanup();

interface MessageResponse {
  ok: boolean;
  error?: string;
  pasted?: boolean;
  pageContext?: PageContext | null;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'paste-code') {
    respond(sendResponse, pasteCodeIntoActivePage(message.code));
    return true;
  }

  if (message?.type === 'get-active-page-context') {
    respond(sendResponse, getActivePageContext(readWindowId(message.windowId)));
    return true;
  }

  return undefined;
});

chrome.tabs.onActivated.addListener(({ windowId }) => notifyActivePageChanged(windowId, true));
chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  if (!tab.active) {
    return;
  }
  if (changeInfo.url !== undefined || changeInfo.status !== undefined) {
    notifyActivePageChanged(tab.windowId, true);
  } else if (changeInfo.title !== undefined) {
    notifyActivePageChanged(tab.windowId, false);
  }
});
chrome.windows.onFocusChanged.addListener((windowId) => {
  if (windowId !== chrome.windows.WINDOW_ID_NONE) {
    notifyActivePageChanged(windowId, true);
  }
});

async function getActivePageContext(windowId: number | undefined): Promise<Partial<MessageResponse>> {
  const tab = await getActiveTab(windowId);
  if (!tab?.url || isRestrictedPage(tab.url)) {
    return { pageContext: null };
  }

  try {
    const url = new URL(tab.url);
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { pageContext: null };
    }
    return {
      pageContext: {
        hostname: url.hostname,
        ...(tab.title ? { title: tab.title.slice(0, 512) } : {})
      }
    };
  } catch {
    return { pageContext: null };
  }
}

function notifyActivePageChanged(windowId: number, clearCurrent: boolean): void {
  sendRuntimeMessage({ type: 'active-page-context-changed', windowId, clearCurrent });
}

async function pasteCodeIntoActivePage(code: unknown): Promise<Partial<MessageResponse>> {
  if (typeof code !== 'string' || code.length === 0 || code.length > 32) {
    throw new Error('Auto-paste code is invalid.');
  }

  const tab = await getActiveTab();
  if (!tab?.id) {
    throw new Error('No active tab is available for auto-paste.');
  }

  if (isRestrictedPage(tab.url)) {
    throw new Error('Auto-paste is unavailable on internal or extension pages.');
  }

  await executeScript(tab.id, 'assets/codePaster.js');
  const response = await sendTabMessage<MessageResponse>(tab.id, { type: 'code-paste:run', code });
  if (!response?.ok) {
    throw new Error(response?.error ?? 'Auto-paste failed.');
  }

  return { pasted: Boolean(response.pasted) };
}

function respond(
  sendResponse: (response: MessageResponse) => void,
  action: Promise<Partial<MessageResponse> | void>
): void {
  action
    .then((payload) => {
      const data = payload && typeof payload === 'object' ? payload : {};
      sendResponse({ ok: true, ...data });
    })
    .catch((error) => {
      sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : 'Request failed.'
      });
    });
}

function getActiveTab(windowId?: number): Promise<chrome.tabs.Tab | undefined> {
  return new Promise((resolve, reject) => {
    const query = windowId === undefined ? { active: true, currentWindow: true } : { active: true, windowId };
    chrome.tabs.query(query, (tabs) => {
      settleChromeCallback(() => resolve(tabs[0]), reject);
    });
  });
}

function readWindowId(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function executeScript(tabId: number, file: string): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.scripting.executeScript(
      {
        target: { tabId },
        files: [file]
      },
      () => settleChromeCallback(resolve, reject)
    );
  });
}

function sendTabMessage<T = unknown>(tabId: number, message: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, { frameId: 0 }, (response: T) => {
      const errorMessage = chrome.runtime.lastError?.message;
      if (errorMessage) {
        reject(new Error(errorMessage));
      } else {
        resolve(response);
      }
    });
  });
}

function sendRuntimeMessage(message: unknown): void {
  chrome.runtime.sendMessage(message, () => {
    void chrome.runtime.lastError;
  });
}

function settleChromeCallback(resolve: () => void, reject: (error: Error) => void): void {
  const message = chrome.runtime.lastError?.message;
  if (message) {
    reject(new Error(message));
  } else {
    resolve();
  }
}

function isRestrictedPage(url: string | undefined): boolean {
  if (!url) {
    return true;
  }

  return /^(chrome|edge|about|moz-extension|chrome-extension|devtools):/i.test(url);
}
