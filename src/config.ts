export const config = {
  NONCE_TAG: '__nc',
  STORAGE_ROOT: '.v2.stor.vlt12',
  // Relay tokens, keys and hashes are 32 bytes
  RELAY_TOKEN_LEN: 32,

  RELAY_TOKEN_B64: 44,

  // 5 min - Matched with config.x.relay.token_timeout
  RELAY_TOKEN_TIMEOUT: 5 * 60 * 1000,

  // 15 min - Matched with config.x.relay.session_timeout
  RELAY_SESSION_TIMEOUT: 15 * 60 * 1000,

  // 5 sec - Ajax request timeout
  RELAY_AJAX_TIMEOUT: 5 * 1000
};
