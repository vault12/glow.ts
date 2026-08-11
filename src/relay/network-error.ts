export class GlowNetworkError extends Error {
  readonly name = 'GlowNetworkError';

  /**
   * @param status HTTP status code, 0 for network-layer failures, 408 for timeouts
   * @param details relay-provided reason from the `X-Error-Details` response header.
   * Most relay rejections share one generic text on purpose; conditions the relay
   * considers safe to reveal (e.g. a full mailbox or an exceeded storage quota)
   * carry a specific message the caller can branch on.
   * @param retryAfter seconds until the relay accepts requests from this sender
   * again, from the `Retry-After` response header on a 429. Undefined when the
   * relay doesn't send the header.
   */
  constructor(public status: number|undefined, public details?: string, public retryAfter?: number) {
    super(details ? `GlowNetworkError status: ${status} (${details})` : `GlowNetworkError status: ${status}`);
  }
}
