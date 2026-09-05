import type { MessageKey } from '../../i18n/messages';

export type SyncStatus = 'off' | 'syncing' | 'ready' | 'pending' | 'error';
export type SyncStatusTone = 'neutral' | 'progress' | 'ok' | 'attention';

/** Short status line shown next to the Browser Sync entry and inside the panel. */
export function getSyncStatusKey(status: SyncStatus): MessageKey {
  switch (status) {
    case 'syncing':
      return 'syncSyncing';
    case 'pending':
      return 'syncPending';
    case 'error':
      return 'syncErrorStatus';
    default:
      return 'syncReady';
  }
}

/** Visual weight of the status: attention states need the user, the rest do not. */
export function getSyncStatusTone(status: SyncStatus): SyncStatusTone {
  switch (status) {
    case 'syncing':
      return 'progress';
    case 'pending':
    case 'error':
      return 'attention';
    case 'ready':
      return 'ok';
    default:
      return 'neutral';
  }
}

export const SYNC_STATUS_DOT: Record<SyncStatusTone, string> = {
  neutral: 'bg-base-content/30',
  progress: 'bg-primary',
  ok: 'bg-success',
  attention: 'bg-warning'
};
