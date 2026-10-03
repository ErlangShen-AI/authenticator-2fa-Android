/**
 * Copies text with the async clipboard API, falling back to a selection-based
 * copy where the API is missing or refused (for example plain HTTP previews).
 */
export async function writeClipboardText(value: string): Promise<void> {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Fall through to the selection-based copy below.
    }
  }

  const input = document.createElement('textarea');
  input.value = value;
  input.setAttribute('readonly', '');
  input.style.position = 'fixed';
  input.style.top = '0';
  input.style.left = '0';
  input.style.width = '1px';
  input.style.height = '1px';
  input.style.opacity = '0';
  document.body.append(input);
  try {
    input.select();
    if (!document.execCommand('copy')) {
      throw new Error('Copy was rejected.');
    }
  } finally {
    input.remove();
  }
}
