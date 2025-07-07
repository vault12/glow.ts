export class GlowNetworkError extends Error {
  readonly name = 'GlowNetworkError';

  constructor(public status: number|undefined) {
    super(`GlowNetworkError status: ${status}`);
  }
}