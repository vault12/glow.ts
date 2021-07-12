export class CommandError extends Error {
  readonly name = 'CommandError';

  constructor(public status: number|undefined) {
    super(`CommandError status: ${status}`);
  }
}