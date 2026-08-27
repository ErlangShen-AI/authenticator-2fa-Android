import { describe, expect, test } from 'vitest';
import { resolvePageScanGesture } from '../../src/lib/auth/pageScanSelection';

describe('resolvePageScanGesture', () => {
  const viewport = { width: 1000, height: 800 };

  test('turns a click into a bounded area centered on the pointer', () => {
    expect(resolvePageScanGesture({ x: 500, y: 400 }, { x: 500, y: 400 }, viewport, 2)).toEqual({
      left: 244,
      top: 144,
      width: 512,
      height: 512,
      devicePixelRatio: 2,
      viewport,
      focus: { x: 500, y: 400 }
    });
  });

  test('treats normal pointer jitter as a click', () => {
    const rect = resolvePageScanGesture({ x: 500, y: 400 }, { x: 508, y: 406 }, viewport, 1);

    expect(rect).toMatchObject({ left: 248, top: 147, focus: { x: 504, y: 403 } });
  });

  test('shifts click areas inside every viewport edge instead of clipping them', () => {
    expect(resolvePageScanGesture({ x: 1, y: 1 }, { x: -5, y: -5 }, viewport, 1)).toMatchObject({
      left: 0,
      top: 0,
      width: 512,
      height: 512
    });
    expect(
      resolvePageScanGesture({ x: 999, y: 799 }, { x: 1005, y: 805 }, viewport, 1)
    ).toMatchObject({
      left: 488,
      top: 288,
      width: 512,
      height: 512
    });
  });

  test('uses the whole visible area when the viewport is smaller than the click area', () => {
    expect(
      resolvePageScanGesture(
        { x: 160, y: 120 },
        { x: 160, y: 120 },
        { width: 320, height: 240 },
        2
      )
    ).toMatchObject({ left: 0, top: 0, width: 320, height: 240 });
  });

  test('caps the physical click area on unusually high-density displays', () => {
    expect(resolvePageScanGesture({ x: 500, y: 400 }, { x: 500, y: 400 }, viewport, 8)).toMatchObject({
      left: 372,
      top: 272,
      width: 256,
      height: 256
    });
  });

  test('preserves normalized exact drag selections at the threshold', () => {
    expect(
      resolvePageScanGesture(
        { x: 800, y: 600 },
        { x: 788, y: 588 },
        viewport,
        1.25
      )
    ).toEqual({
      left: 788,
      top: 588,
      width: 12,
      height: 12,
      devicePixelRatio: 1.25,
      viewport
    });
  });

  test('does not reinterpret a long thin drag as a click', () => {
    expect(resolvePageScanGesture({ x: 100, y: 100 }, { x: 250, y: 105 }, viewport, 1)).toBeNull();
  });
});
