const MIN_SCAN_DRAG_SIZE = 12;
const CLICK_SCAN_CSS_SIDE = 512;
const MAX_CLICK_SCAN_BITMAP_SIDE = 2048;

interface Point {
  x: number;
  y: number;
}

interface Viewport {
  width: number;
  height: number;
}

export interface PageScanCaptureRect {
  left: number;
  top: number;
  width: number;
  height: number;
  devicePixelRatio: number;
  // Older injected scanner versions omit these fields.
  viewport?: Viewport;
  focus?: Point;
}

export function resolvePageScanGesture(
  start: Point,
  end: Point,
  viewport: Viewport,
  devicePixelRatio: number
): PageScanCaptureRect | null {
  if (
    !isFinitePoint(start) ||
    !isFinitePoint(end) ||
    !isPositiveFinite(viewport.width) ||
    !isPositiveFinite(viewport.height)
  ) {
    return null;
  }

  const ratio = isPositiveFinite(devicePixelRatio) ? devicePixelRatio : 1;
  const boundedStart = clampPoint(start, viewport);
  const boundedEnd = clampPoint(end, viewport);
  const width = Math.abs(boundedEnd.x - boundedStart.x);
  const height = Math.abs(boundedEnd.y - boundedStart.y);
  const isClick = width < MIN_SCAN_DRAG_SIZE && height < MIN_SCAN_DRAG_SIZE;

  if (isClick) {
    return getClickCaptureRect(
      {
        x: (boundedStart.x + boundedEnd.x) / 2,
        y: (boundedStart.y + boundedEnd.y) / 2
      },
      viewport,
      ratio
    );
  }

  const isValidDrag = width >= MIN_SCAN_DRAG_SIZE && height >= MIN_SCAN_DRAG_SIZE;
  if (!isValidDrag) {
    return null;
  }

  return {
    left: Math.min(boundedStart.x, boundedEnd.x),
    top: Math.min(boundedStart.y, boundedEnd.y),
    width,
    height,
    devicePixelRatio: ratio,
    viewport
  };
}

function getClickCaptureRect(
  focus: Point,
  viewport: Viewport,
  devicePixelRatio: number
): PageScanCaptureRect {
  // Keep the search local and cap its decoded size on unusually dense displays.
  const side = Math.min(
    CLICK_SCAN_CSS_SIDE,
    MAX_CLICK_SCAN_BITMAP_SIDE / devicePixelRatio
  );
  const width = Math.min(side, viewport.width);
  const height = Math.min(side, viewport.height);

  return {
    left: clamp(focus.x - width / 2, 0, viewport.width - width),
    top: clamp(focus.y - height / 2, 0, viewport.height - height),
    width,
    height,
    devicePixelRatio,
    viewport,
    focus
  };
}

function clampPoint(point: Point, viewport: Viewport): Point {
  return {
    x: clamp(point.x, 0, viewport.width),
    y: clamp(point.y, 0, viewport.height)
  };
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(Math.max(value, minimum), maximum);
}

function isPositiveFinite(value: number): boolean {
  return Number.isFinite(value) && value > 0;
}

function isFinitePoint(point: Point): boolean {
  return Number.isFinite(point.x) && Number.isFinite(point.y);
}
