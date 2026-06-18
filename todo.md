# cTLS TODO

## Crypto

- [ ] **KeyShare length is hardcoded to 32 (X25519 only).** `CTLS_SIZE_KEY_SHARE = 32U` used everywhere in `crypto.c` and `extensions.c`. Must derive length from `template->dhe_group.key_share_length`, set per group at `ctls_crypto_init` time. Affects `ctls_ephemeral_public_key_import`, `ctls_ephemeral_public_key_export`, `ctls_shared_ephemeral_secret_generate`, and KeyShare extension serialization / deserialization.

## General

- [ ] **Bounds checks before every read/write operation.** Every buffer write must verify `offset + write_size <= max_configured_length` before proceeding; every read must verify `offset + read_size <= buffer_length`. Max lengths and counts are defined in `config.h` and `types.h` (e.g. `CTLS_SIZE_WIRE_BUFFER`, `CTLS_COUNT_ALPN`, `CTLS_SIZE_MAX_ALPN_PROTOCOL_NAME`, `CTLS_SIZE_MAX_DISTINGUISHED_NAME`, etc.). Violation must return the appropriate status code (`CTLS_STATUS_BUFFER_OVERFLOW`, `CTLS_STATUS_BUFFER_TOO_SMALL`, or `CTLS_STATUS_BOUNDS_EXCEEDED`) instead of writing out of bounds.
