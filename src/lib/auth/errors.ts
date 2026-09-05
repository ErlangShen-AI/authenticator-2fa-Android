export class AccountChangedError extends Error {
  constructor() {
    super('This account changed. Reopen it and try again.');
  }
}

/** Message of a thrown value, or `fallback` when it carries none. */
export function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}
