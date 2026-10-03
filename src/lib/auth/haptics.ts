/** Short confirmation tick for commits on devices that expose the vibration API. */
export function tapHaptic(duration = 10): void {
  try {
    navigator.vibrate?.(duration);
  } catch {
    // Feedback stays visual where vibration is unavailable or blocked.
  }
}
