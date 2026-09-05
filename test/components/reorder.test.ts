import { describe, expect, test } from 'vitest';
import {
  getAutoScrollVelocity,
  isReorderCurrent,
  moveItem,
  rubberbandOffset
} from '../../src/lib/components/auth/reorder';

describe('account reorder motion', () => {
  test('keeps refreshed drag positions only when the same accounts remain in the same order', () => {
    const source = ['a', 'b', 'c', 'd'];
    const accounts = (ids: string[]) => ids.map((id) => ({ id, label: `${id} updated`, counter: 10 }));

    expect(isReorderCurrent(accounts(source), source)).toBe(true);
    for (const changed of [
      ['b', 'c', 'd'],
      ['a', 'b', 'c', 'd', 'e'],
      ['a', 'b-copy', 'c', 'd'],
      ['a', 'c', 'b', 'd']
    ]) {
      expect(isReorderCurrent(accounts(changed), source)).toBe(false);
    }
  });

  test('returns frame-rate-independent auto-scroll velocity near an available edge', () => {
    expect(
      getAutoScrollVelocity({
        pointerY: 28,
        top: 0,
        bottom: 500,
        scrollTop: 100,
        maxScrollTop: 400
      })
    ).toBe(-540);
    expect(
      getAutoScrollVelocity({
        pointerY: 486,
        top: 0,
        bottom: 500,
        scrollTop: 100,
        maxScrollTop: 400
      })
    ).toBe(810);
  });

  test('stops auto-scroll at content boundaries and away from the edge', () => {
    expect(
      getAutoScrollVelocity({
        pointerY: 0,
        top: 0,
        bottom: 500,
        scrollTop: 0,
        maxScrollTop: 400
      })
    ).toBe(0);
    expect(
      getAutoScrollVelocity({
        pointerY: 500,
        top: 0,
        bottom: 500,
        scrollTop: 400,
        maxScrollTop: 400
      })
    ).toBe(0);
    expect(
      getAutoScrollVelocity({
        pointerY: 250,
        top: 0,
        bottom: 500,
        scrollTop: 100,
        maxScrollTop: 400
      })
    ).toBe(0);
  });

  test('rubber-bands symmetrically beyond the reorder bounds', () => {
    expect(rubberbandOffset(40, 0, 80, 64)).toBe(40);
    expect(rubberbandOffset(-100, 0, 80, 64)).toBeCloseTo(-29.58, 2);
    expect(rubberbandOffset(180, 0, 80, 64)).toBeCloseTo(109.58, 2);
  });

  test('moves an item without mutating the source list', () => {
    const source = ['a', 'b', 'c'];

    expect(moveItem(source, 0, 2)).toEqual(['b', 'c', 'a']);
    expect(source).toEqual(['a', 'b', 'c']);
    expect(moveItem(source, -1, 2)).toEqual(source);
  });
});
