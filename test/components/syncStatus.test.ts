import { describe, expect, test } from 'vitest';
import {
  getSyncStatusKey,
  getSyncStatusTone,
  SYNC_STATUS_DOT
} from '../../src/lib/components/auth/syncStatus';

describe('sync status presentation', () => {
  test('maps every status to a message key', () => {
    expect(getSyncStatusKey('syncing')).toBe('syncSyncing');
    expect(getSyncStatusKey('pending')).toBe('syncPending');
    expect(getSyncStatusKey('error')).toBe('syncErrorStatus');
    expect(getSyncStatusKey('ready')).toBe('syncReady');
    expect(getSyncStatusKey('off')).toBe('syncReady');
  });

  test('flags retry and error states as needing attention', () => {
    expect(getSyncStatusTone('pending')).toBe('attention');
    expect(getSyncStatusTone('error')).toBe('attention');
    expect(getSyncStatusTone('syncing')).toBe('progress');
    expect(getSyncStatusTone('ready')).toBe('ok');
    expect(getSyncStatusTone('off')).toBe('neutral');
  });

  test('every tone has a dot color', () => {
    for (const tone of ['neutral', 'progress', 'ok', 'attention'] as const) {
      expect(SYNC_STATUS_DOT[tone]).toMatch(/^bg-/);
    }
  });
});
