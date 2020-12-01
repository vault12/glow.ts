export const config = {

  COMM_KEY_TAG: '__::commKey::__',
  NONCE_TAG: '__nc',
  STORAGE_ROOT: '.v2.stor.vlt12',
  // Relay tokens, keys and hashes are 32 bytes
  RELAY_TOKEN_LEN: 32,

  RELAY_TOKEN_B64: 44,

  // 5 min - Matched with config.x.relay.token_timeout
  RELAY_TOKEN_TIMEOUT: 5 * 60 * 1000
};
