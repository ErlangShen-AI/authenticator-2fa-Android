import { assertQrImageBounds, decodeQrImageData, type QrDecodeFocus } from './qrDecode';
import type { PageScanCaptureRect } from './pageScanSelection';

const PAGE_SCAN_FAILED = 'Page scan failed.';

interface CaptureBounds {
  left: number;
  top: number;
  width: number;
  height: number;
}

interface QrBitmapRegion extends CaptureBounds {
  focus?: QrDecodeFocus;
}

export async function decodeQrDataUrlInWorker(dataUrl: string, crop: PageScanCaptureRect) {
  if (typeof OffscreenCanvas === 'undefined' || typeof createImageBitmap === 'undefined') {
    throw new Error('Page scan decoding is unavailable here.');
  }

  const blob = dataUrlToBlob(dataUrl);
  const bitmap = await createImageBitmap(blob);
  try {
    const region = getQrBitmapRegion(bitmap.width, bitmap.height, crop);
    assertQrImageBounds(region.width, region.height);
    const canvas = new OffscreenCanvas(region.width, region.height);
    const context = canvas.getContext('2d', { willReadFrequently: true });
    if (!context) {
      throw new Error('Canvas rendering is unavailable.');
    }

    context.fillStyle = '#fff';
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.drawImage(
      bitmap,
      region.left,
      region.top,
      region.width,
      region.height,
      0,
      0,
      canvas.width,
      canvas.height
    );

    const decoded = await decodeQrImageData(
      context.getImageData(0, 0, canvas.width, canvas.height),
      region.focus
    );
    if (!decoded) {
      throw new Error('No QR code was found near that click or in the selected area.');
    }
    return decoded;
  } finally {
    bitmap.close();
  }
}

export function getQrBitmapRegion(
  bitmapWidth: number,
  bitmapHeight: number,
  crop: PageScanCaptureRect
): QrBitmapRegion {
  const hasValidBitmapSize =
    Number.isSafeInteger(bitmapWidth) &&
    bitmapWidth > 0 &&
    Number.isSafeInteger(bitmapHeight) &&
    bitmapHeight > 0;
  if (!hasValidBitmapSize) {
    throw new Error(PAGE_SCAN_FAILED);
  }

  if (!isPageScanCaptureRect(crop)) {
    throw new Error(PAGE_SCAN_FAILED);
  }

  let scaleX = crop.devicePixelRatio;
  let scaleY = crop.devicePixelRatio;
  if (crop.viewport) {
    scaleX = bitmapWidth / crop.viewport.width;
    scaleY = bitmapHeight / crop.viewport.height;
  }

  const left = Math.max(0, Math.floor(crop.left * scaleX));
  const top = Math.max(0, Math.floor(crop.top * scaleY));
  const right = Math.min(bitmapWidth, Math.ceil((crop.left + crop.width) * scaleX));
  const bottom = Math.min(bitmapHeight, Math.ceil((crop.top + crop.height) * scaleY));
  if (right <= left || bottom <= top) {
    throw new Error(PAGE_SCAN_FAILED);
  }

  const region: QrBitmapRegion = {
    left,
    top,
    width: right - left,
    height: bottom - top
  };
  if (crop.focus) {
    region.focus = {
      x: clamp(crop.focus.x * scaleX - left, 0, region.width - 1),
      y: clamp(crop.focus.y * scaleY - top, 0, region.height - 1)
    };
  }

  return region;
}

export function isPageScanCaptureRect(value: unknown): value is PageScanCaptureRect {
  if (!isRecord(value)) {
    return false;
  }

  const { left, top, width, height, devicePixelRatio, viewport, focus } = value;
  if (
    !isNonNegativeNumber(left) ||
    !isNonNegativeNumber(top) ||
    !isPositiveNumber(width) ||
    !isPositiveNumber(height) ||
    !isPositiveNumber(devicePixelRatio)
  ) {
    return false;
  }

  const bounds = { left, top, width, height };
  return hasValidViewport(viewport, bounds) && hasValidFocus(focus, bounds);
}

function hasValidViewport(value: unknown, bounds: CaptureBounds): boolean {
  if (value === undefined) {
    return true;
  }
  if (!isRecord(value)) {
    return false;
  }

  const { width, height } = value;
  if (!isPositiveNumber(width) || !isPositiveNumber(height)) {
    return false;
  }

  return bounds.left + bounds.width <= width && bounds.top + bounds.height <= height;
}

function hasValidFocus(value: unknown, bounds: CaptureBounds): boolean {
  if (value === undefined) {
    return true;
  }
  if (!isRecord(value)) {
    return false;
  }

  if (!isNonNegativeNumber(value.x) || !isNonNegativeNumber(value.y)) {
    return false;
  }

  const insideHorizontally = value.x >= bounds.left && value.x <= bounds.left + bounds.width;
  const insideVertically = value.y >= bounds.top && value.y <= bounds.top + bounds.height;
  return insideHorizontally && insideVertically;
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(Math.max(value, minimum), maximum);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isNonNegativeNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function isPositiveNumber(value: unknown): value is number {
  return isNonNegativeNumber(value) && value > 0;
}

export function dataUrlToBlob(dataUrl: string) {
  const match = /^data:([^,]*),(.*)$/s.exec(dataUrl);
  if (!match) {
    throw new Error(PAGE_SCAN_FAILED);
  }

  const metadata = match[1] ?? '';
  const encodedData = match[2] ?? '';
  const metadataParts = metadata.split(';').filter(Boolean);
  const mimeType = metadataParts.find((part) => part.includes('/')) ?? 'application/octet-stream';
  const isBase64 = metadataParts.some((part) => part.toLowerCase() === 'base64');

  if (!isBase64) {
    return new Blob([new TextEncoder().encode(decodeURIComponent(encodedData))], {
      type: mimeType
    });
  }

  const binary = atob(encodedData);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return new Blob([bytes], { type: mimeType });
}
