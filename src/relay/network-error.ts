export class NetworkError extends Error {
  readonly name = 'NetworkError';

  constructor(public status: number|undefined) {
    super(`NetworkError status: ${status}`);
  }
}