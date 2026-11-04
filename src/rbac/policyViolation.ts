/** Thrown when a permitted tool call asks for fields or filters outside the caller's allowlist. */
export class PolicyViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyViolationError';
  }
}
