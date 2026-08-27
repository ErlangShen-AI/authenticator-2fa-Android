import {
  prepareZXingModule,
  readBarcodes,
  type ReaderOptions,
  type ReadResult
} from 'zxing-wasm/reader';
import readerWasmUrl from 'zxing-wasm/reader/zxing_reader.wasm?url';

export const MAX_QR_IMAGE_PIXELS = 16_000_000;
export const QR_IMAGE_TOO_LARGE_ERROR = 'Selected image is too large to scan as a QR code.';

const READER_OPTIONS = {
  formats: ['QRCode'],
  maxNumberOfSymbols: 1,
  tryHarder: true
} satisfies ReaderOptions;

const FOCUSED_READER_OPTIONS = {
  ...READER_OPTIONS,
  maxNumberOfSymbols: 8
} satisfies ReaderOptions;

export interface QrDecodeFocus {
  x: number;
  y: number;
}

type QrEdge = readonly [QrDecodeFocus, QrDecodeFocus];

prepareZXingModule({
  overrides: {
    locateFile: (path: string, prefix: string) =>
      path.endsWith('.wasm') ? readerWasmUrl : prefix + path
  }
});

export async function decodeQrImageData(
  imageData: {
    data: Uint8ClampedArray | Uint8Array;
    width: number;
    height: number;
  },
  focus?: QrDecodeFocus
) {
  if (
    !Number.isSafeInteger(imageData.width) ||
    imageData.width <= 0 ||
    !Number.isSafeInteger(imageData.height) ||
    imageData.height <= 0
  ) {
    return '';
  }

  assertQrImageBounds(imageData.width, imageData.height);
  if (imageData.data.length < imageData.width * imageData.height * 4) {
    return '';
  }

  const hasFocus = isFiniteFocus(focus);
  const results = await readBarcodes(
    imageData as ImageData,
    hasFocus ? FOCUSED_READER_OPTIONS : READER_OPTIONS
  );
  const decoded = results.filter(({ text }) => text);
  if (!hasFocus || decoded.length < 2) {
    return decoded[0]?.text ?? '';
  }

  return findClosestQr(decoded, focus).text;
}

export function assertQrImageBounds(width: number, height: number): void {
  if (width * height > MAX_QR_IMAGE_PIXELS) {
    throw new Error(QR_IMAGE_TOO_LARGE_ERROR);
  }
}

function findClosestQr(results: ReadResult[], focus: QrDecodeFocus): ReadResult {
  let closest = results[0]!;
  let closestProximity = getQrProximity(closest, focus);

  for (let index = 1; index < results.length; index += 1) {
    const candidate = results[index]!;
    const candidateProximity = getQrProximity(candidate, focus);
    const nearerEdge =
      candidateProximity.edgeDistanceSquared < closestProximity.edgeDistanceSquared;
    const nearerCenter =
      candidateProximity.edgeDistanceSquared === closestProximity.edgeDistanceSquared &&
      candidateProximity.centerDistanceSquared < closestProximity.centerDistanceSquared;

    if (nearerEdge || nearerCenter) {
      closest = candidate;
      closestProximity = candidateProximity;
    }
  }

  return closest;
}

function getQrProximity(result: ReadResult, focus: QrDecodeFocus) {
  const { topLeft, topRight, bottomLeft, bottomRight } = result.position;
  const edges: QrEdge[] = [
    [topLeft, topRight],
    [topRight, bottomRight],
    [bottomRight, bottomLeft],
    [bottomLeft, topLeft]
  ];
  const center = {
    x: (topLeft.x + topRight.x + bottomRight.x + bottomLeft.x) / 4,
    y: (topLeft.y + topRight.y + bottomRight.y + bottomLeft.y) / 4
  };
  let edgeDistanceSquared = 0;
  if (!isInsideQr(focus, edges)) {
    edgeDistanceSquared = getClosestEdgeDistanceSquared(focus, edges);
  }

  return {
    edgeDistanceSquared,
    centerDistanceSquared: getSquaredDistance(focus, center)
  };
}

function isInsideQr(point: QrDecodeFocus, edges: QrEdge[]): boolean {
  let expectedSide = 0;

  for (const [start, end] of edges) {
    const side = getSideOfEdge(point, start, end);
    if (side === 0) {
      continue;
    }
    if (expectedSide === 0) {
      expectedSide = side;
      continue;
    }
    if (side !== expectedSide) {
      return false;
    }
  }

  return expectedSide !== 0;
}

function getSideOfEdge(
  point: QrDecodeFocus,
  start: QrDecodeFocus,
  end: QrDecodeFocus
): number {
  const edgeX = end.x - start.x;
  const edgeY = end.y - start.y;
  const pointX = point.x - start.x;
  const pointY = point.y - start.y;
  const crossProduct = edgeX * pointY - edgeY * pointX;
  return Math.sign(crossProduct);
}

function getClosestEdgeDistanceSquared(point: QrDecodeFocus, edges: QrEdge[]): number {
  let closestDistance = Number.POSITIVE_INFINITY;

  for (const [start, end] of edges) {
    closestDistance = Math.min(closestDistance, getSquaredSegmentDistance(point, start, end));
  }

  return closestDistance;
}

function getSquaredSegmentDistance(
  point: QrDecodeFocus,
  start: QrDecodeFocus,
  end: QrDecodeFocus
): number {
  const edgeX = end.x - start.x;
  const edgeY = end.y - start.y;
  const edgeLengthSquared = edgeX ** 2 + edgeY ** 2;
  if (edgeLengthSquared === 0) {
    return getSquaredDistance(point, start);
  }

  const pointX = point.x - start.x;
  const pointY = point.y - start.y;
  const dotProduct = pointX * edgeX + pointY * edgeY;
  const projection = dotProduct / edgeLengthSquared;
  if (projection < 0) {
    return getSquaredDistance(point, start);
  }
  if (projection > 1) {
    return getSquaredDistance(point, end);
  }

  const closestPoint = {
    x: start.x + edgeX * projection,
    y: start.y + edgeY * projection
  };
  return getSquaredDistance(point, closestPoint);
}

function getSquaredDistance(first: QrDecodeFocus, second: QrDecodeFocus): number {
  return (first.x - second.x) ** 2 + (first.y - second.y) ** 2;
}

function isFiniteFocus(point: QrDecodeFocus | undefined): point is QrDecodeFocus {
  return Boolean(point && Number.isFinite(point.x) && Number.isFinite(point.y));
}
