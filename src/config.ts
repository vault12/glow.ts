export const config = {
  NONCE_TAG: '__nc',
  STORAGE_ROOT: '.v2.stor.vlt12',
  // Relay tokens, keys and hashes are 32 bytes
  RELAY_TOKEN_LEN: 32,
  // 5 min - Token expiration on the server side, matched with config.x.relay.token_timeout on Zax server
  RELAY_TOKEN_TIMEOUT: 5 * 60 * 1000,
  // 5 sec - Ajax request timeout
  RELAY_AJAX_TIMEOUT: 5 * 1000
};
