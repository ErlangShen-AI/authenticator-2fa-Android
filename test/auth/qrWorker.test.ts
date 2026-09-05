import { describe, expect, test } from 'vitest';
import {
  dataUrlToBlob,
  getQrBitmapRegion,
  isPageScanCaptureRect
} from '../../src/lib/auth/qrWorker';

describe('getQrBitmapRegion', () => {
  test('maps viewport coordinates using the screenshot dimensions', () => {
    expect(
      getQrBitmapRegion(2000, 1000, {
        left: 100,
        top: 200,
        width: 300,
        height: 400,
        devicePixelRatio: 3,
        viewport: { width: 1000, height: 800 },
        focus: { x: 200, y: 300 }
      })
    ).toEqual({
      left: 200,
      top: 250,
      width: 600,
      height: 500,
      focus: { x: 200, y: 125 }
    });
  });

  test('rounds fractional crop starts outward and clamps edge focus', () => {
    expect(
      getQrBitmapRegion(1250, 1000, {
        left: 900.2,
        top: 700.2,
        width: 99.8,
        height: 99.8,
        devicePixelRatio: 1,
        viewport: { width: 1000, height: 800 },
        focus: { x: 1000, y: 800 }
      })
    ).toEqual({ left: 1125, top: 875, width: 125, height: 125, focus: { x: 124, y: 124 } });
  });

  test('supports the legacy device-pixel-ratio mapping', () => {
    expect(
      getQrBitmapRegion(2000, 1200, {
        left: 10,
        top: 20,
        width: 100,
        height: 80,
        devicePixelRatio: 2
      })
    ).toEqual({ left: 20, top: 40, width: 200, height: 160 });
  });

  test('rejects invalid or out-of-bounds geometry before canvas allocation', () => {
    expect(() =>
      getQrBitmapRegion(1000, 800, {
        left: -1,
        top: 0,
        width: 100,
        height: 100,
        devicePixelRatio: 1
      })
    ).toThrow('Page scan failed.');
    expect(() =>
      getQrBitmapRegion(1000, 800, {
        left: 1100,
        top: 0,
        width: 100,
        height: 100,
        devicePixelRatio: 1
      })
    ).toThrow('Page scan failed.');
    expect(() =>
      getQrBitmapRegion(1000, 800, {
        left: 900,
        top: 0,
        width: 200,
        height: 100,
        devicePixelRatio: 1,
        viewport: { width: 1000, height: 800 }
      })
    ).toThrow('Page scan failed.');
    expect(
      isPageScanCaptureRect({
        left: 0,
        top: 0,
        width: 100,
        height: 100,
        devicePixelRatio: 1,
        focus: { x: 50 }
      })
    ).toBe(false);
  });
});

describe('dataUrlToBlob', () => {
  test('converts base64 data URLs without using fetch', async () => {
    const blob = dataUrlToBlob('data:image/png;base64,SGVsbG8=');

    expect(blob.type).toBe('image/png');
    expect(await blob.text()).toBe('Hello');
  });

  test('converts percent-encoded data URLs', async () => {
    const blob = dataUrlToBlob('data:text/plain;charset=utf-8,Hello%20world');

    expect(blob.type).toBe('text/plain');
    expect(await blob.text()).toBe('Hello world');
  });

  test('rejects non-data URLs', () => {
    expect(() => dataUrlToBlob('https://example.com/qr.png')).toThrow('Page scan failed.');
  });
});
