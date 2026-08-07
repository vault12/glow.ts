export class GlowNetworkError extends Error {
  readonly name = 'GlowNetworkError';

  /**
   * @param status HTTP status code, 0 for network-layer failures, 408 for timeouts
   * @param details relay-provided reason from the `X-Error-Details` response header.
   * Most relay rejections share one generic text on purpose; conditions the relay
   * considers safe to reveal (e.g. a full mailbox or an exceeded storage quota)
   * carry a specific message the caller can branch on.
   */
  constructor(public status: number|undefined, public details?: string) {
    super(details ? `GlowNetworkError status: ${status} (${details})` : `GlowNetworkError status: ${status}`);
  }
}
