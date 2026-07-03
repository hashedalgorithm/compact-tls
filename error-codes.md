# cTLS Error Code Registry

`ctls_err_t` — proposed flat `uint16_t` replacing `ctls_op_status_t`.

Range bands encode the subsystem, so `source` field is no longer needed.
`external_code` is dropped; crypto callers that need the raw PSA status should
store it separately before returning a `ctls_err_t`.

---

## Type definition (proposed)

```c
typedef uint16_t ctls_status_t;

#define CTLS_STATUS_SUCCESS  0x0000
```

---

## Range Summary

| Range         | Subsystem               |
|---------------|-------------------------|
| 0x0000        | Success                 |
| 0x0001–0x0031 | General / Parameter     |
| 0x0032–0x0063 | Buffer / Memory         |
| 0x0064–0x00C7 | Crypto (PSA-backed)     |
| 0x00C8–0x012B | Extension Ser/Deser     |
| 0x012C–0x015D | Record Layer            |
| 0x015E–0x018F | Handshake Messages      |
| 0x0190–0x01C1 | Template / Profile      |
| 0x01C2–0x01F3 | Transport               |
| 0x01F4–0x0225 | Handshake State Machine |
| 0x0226–0x0240 | Alert Mapping           |

---

## 0x0000 — Success

| Code   | Name               | Reason / Trigger                   |
|--------|--------------------|------------------------------------|
| 0x0000 | `CTLS_STATUS_SUCCESS` | Operation completed without error. |

---

## 0x0001–0x0031 — General / Parameter Errors

These fire before any subsystem logic executes.

| Code   | Name                       | Reason / Trigger                                                                                                                                                          |
|--------|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x0001 | `CTLS_STATUS_NULL_PTR`        | A required pointer argument was NULL. Generic catch-all for `CTLS_CHECK_NULL`.                                                                                            |
| 0x0002 | `CTLS_STATUS_NULL_BUFFER`     | The `buffer` pointer specifically was NULL. Distinct from a NULL struct so the caller knows which arg to fix.                                                             |
| 0x0003 | `CTLS_STATUS_NULL_OFFSET`     | The `offset` pointer was NULL. Offset is a write-back argument; NULL here is a programming error in the caller.                                                           |
| 0x0004 | `CTLS_STATUS_NULL_STRUCT`     | The primary struct pointer (e.g. `hsmg`, `record`, `template`, `crypto`) was NULL. Caller forgot to allocate/pass the object.                                             |
| 0x0005 | `CTLS_STATUS_INVALID_ARG`     | A non-pointer argument held an illegal value (enum out of defined range, zero where non-zero required, etc.).                                                             |
| 0x0006 | `CTLS_STATUS_UNKNOWN`         | Unclassified internal error. Should not appear in production; means a code path returned without setting a real code.                                                     |
| 0x0007 | `CTLS_STATUS_NOT_IMPLEMENTED` | The function exists and is a valid call for this build, but its body is an unfinished stub — no role/context issue, just no logic written yet (e.g. `ctls_hsmg_certificate_request_create`, `ctls_extn_encrypted_extensions_create`, `ctls_extn_certificate_request_create`). |
| 0x0008 | `CTLS_STATUS_INVALID_INVOCATION` | The function has real logic, but it was called in a build/role that isn't supposed to call it at all. Two shapes: (1) a `ctls_core_*_internal_op` hook's `#else` branch — built under neither `CTLS_CLIENT` nor `CTLS_SERVER`; (2) `ctls_connect`/`ctls_accept` called on the wrong role's build (e.g. `ctls_connect` on a `CTLS_SERVER` build, or vice versa) — right function, wrong role. |
| 0x0009 | `CTLS_STATUS_SENT_ALERT` | Reserved sentinel, currently unused. `ctls_alert_send` now returns the *original* status on success (see 0x0226-0x0240 below) instead of this code, so the caller still sees the real failure. |

---

## 0x0032–0x0063 — Buffer / Memory Errors

| Code   | Name                        | Reason / Trigger                                                                                                                                                                                               |
|--------|-----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x0032 | `CTLS_STATUS_BUFFER_OVERFLOW`  | A write would exceed the known buffer boundary (`sizeof(field) + *offset > buffer_size`). Fired in `ctls_recd_client_hello_to_wire` content-type and profile-id writes.                                        |
| 0x0033 | `CTLS_STATUS_BUFFER_TOO_SMALL` | Output buffer is smaller than the minimum required for the result. Distinct from overflow: overflow is a bounds check on a write; this is a capacity pre-check. Also maps to PSA `PSA_ERROR_BUFFER_TOO_SMALL`. |
| 0x0034 | `CTLS_STATUS_BOUNDS_EXCEEDED`  | `CTLS_CHECK_BOUNDS`: `offset + size > limit`. Fired in `ctls_unified_header_deserialize` when fewer than 2 bytes remain in the incoming record.                                                                |

---

## 0x0064–0x00C7 — Crypto Errors (PSA-backed)

All errors in this band originate inside crypto operations backed by Mbed TLS PSA Crypto.

| Code   | Name                                       | Reason / Trigger                                                                                                                                   |
|--------|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x0064 | `CTLS_STATUS_CRYPTO_INIT_FAILED`              | `psa_crypto_init()` returned non-success. PSA subsystem not usable.                                                                                |
| 0x0065 | `CTLS_STATUS_CRYPTO_INVALID_SIGNATURE`        | `PSA_ERROR_INVALID_SIGNATURE` — signature verification failed (wrong key or tampered data).                                                        |
| 0x0066 | `CTLS_STATUS_CRYPTO_INVALID_ARG`              | `PSA_ERROR_INVALID_ARGUMENT` — bad algorithm ID, wrong key type, or zero-length input passed to a PSA function.                                    |
| 0x0067 | `CTLS_STATUS_CRYPTO_NOT_SUPPORTED`            | `PSA_ERROR_NOT_SUPPORTED` — algorithm or key type not compiled into the PSA build.                                                                 |
| 0x0068 | `CTLS_STATUS_CRYPTO_INSUFFICIENT_ENTROPY`     | `PSA_ERROR_INSUFFICIENT_ENTROPY` — platform RNG could not generate requested bytes.                                                                |
| 0x0069 | `CTLS_STATUS_CRYPTO_KEY_GEN_FAILED`           | `psa_generate_key()` failed; ephemeral ECDHE key pair could not be created.                                                                        |
| 0x006A | `CTLS_STATUS_CRYPTO_KEY_EXPORT_FAILED`        | `psa_export_public_key()` or `psa_import_key()` failed; key material could not be read or loaded.                                                  |
| 0x006B | `CTLS_STATUS_CRYPTO_ECDH_FAILED`              | `psa_raw_key_agreement()` failed; shared ephemeral secret derivation failed.                                                                       |
| 0x006C | `CTLS_STATUS_CRYPTO_HKDF_EXTRACT_FAILED`      | PSA HKDF-Extract operation failed (early secret or handshake secret derivation).                                                                   |
| 0x006D | `CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED`       | PSA HKDF-Expand operation failed (derived secret, traffic secrets, write keys, IVs, or finished key derivation).                                   |
| 0x006E | `CTLS_STATUS_CRYPTO_HASH_FAILED`              | `psa_hash_setup`, `psa_hash_update`, `psa_hash_finish`, or `psa_hash_clone` returned non-success. Transcript hash is broken.                       |
| 0x006F | `CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED`      | `psa_aead_decrypt()` failed; either the tag check failed (authentication failure) or a PSA internal error.                                         |
| 0x0070 | `CTLS_STATUS_CRYPTO_AEAD_ENCRYPT_FAILED`      | `psa_aead_encrypt()` failed.                                                                                                                       |
| 0x0071 | `CTLS_STATUS_CRYPTO_UNSUPPORTED_CIPHER_SUITE` | Cipher suite value has no PSA hash algorithm mapping in `ctls_psa_hash_algorithm_set`. New cipher suite added to enum without updating the switch. |
| 0x0072 | `CTLS_STATUS_CRYPTO_UNSUPPORTED_DHE_GROUP`    | DHE group has no PSA ECC family mapping in `ctls_psa_ecc_family_set`. New group added to enum without updating the switch.                         |
| 0x0073 | `CTLS_STATUS_CRYPTO_RANDOM_FAILED`            | `psa_generate_random()` failed in `ctls_random_generate`; random nonce or client-random could not be produced.                                     |
| 0x0074 | `CTLS_STATUS_CRYPTO_SIGNATURE_FAILED`         | PSA signature operation failed.                                                                                                                    |
| 0x0075 | `CTLS_STATUS_CRYPTO_KEY_IMPORT_FAILED`        | `psa_import_key()` failed; key material could not be loaded into a transient PSA key handle.                                                       |
| 0x0077 | `CTLS_STATUS_CRYPTO_SIGNATURE_VERIFY_FAILED`  | `psa_verify_message()` failed; peer's CertificateVerify signature did not match the reconstructed signing content.                                 |
| 0x0078 | `CTLS_STATUS_CRYPTO_HMAC_VERIFY_DATA_FAILED`  | `psa_mac_compute()` or comparison of `verify_data` failed; received Finished message did not match the expected HMAC over the transcript hash.     |
| 0x0079 | `CTLS_STATUS_CRYPTO_UNKNOWN`                  | PSA returned an error code not explicitly mapped in `ctls_psa_error_map`. Raw PSA status must be logged separately.                                |

### 0x007A–0x007E: Transcript hash sub-operations

| Code   | Name                                          | Reason / Trigger                                                                                                   |
|--------|-----------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| 0x007A | `CTLS_STATUS_CRYPTO_HASH_INIT_FAILED`         | `psa_hash_setup()` failed in `ctls_transcript_hash_init`. Hash operator could not be initialized.                  |
| 0x007B | `CTLS_STATUS_CRYPTO_HASH_CALC_FAILED`         | `psa_hash_update()` failed in `ctls_transcript_hash_calculate`. Running transcript update rejected input bytes.    |
| 0x007C | `CTLS_STATUS_CRYPTO_HASH_UPD_FAILED`          | `psa_hash_update()` failed in `ctls_transcript_hash_update`. Individual message bytes could not be absorbed.       |
| 0x007D | `CTLS_STATUS_CRYPTO_HASH_SNAP_CLONE_FAILED`   | `psa_hash_clone()` failed when snapshotting the running hash to produce an intermediate transcript digest.         |
| 0x007E | `CTLS_STATUS_CRYPTO_HASH_SNAP_FINISH_FAILED`  | `psa_hash_finish()` failed on the cloned operator when finalizing the snapshot digest.                             |

### 0x0084–0x008B: Early secret derivation

| Code   | Name                                              | Reason / Trigger                                                                                                                   |
|--------|---------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| 0x0084 | `CTLS_STATUS_CRYPTO_EARLY_SECRET_EXTRACT_FAILED`  | `psa_key_derivation_output_key()` failed in `ctls_early_secret_generate`. Early secret PSA key could not be produced.             |
| 0x0085 | `CTLS_STATUS_CRYPTO_HKDF_EXTRACT_OP_FAILED`      | PSA HKDF-Extract operation (setup/input/output sequence) failed in the generic extract helper.                                     |
| 0x0086 | `CTLS_STATUS_CRYPTO_MASTER_SECRET_EXTRACT_FAILED` | HKDF-Extract failed in `ctls_master_secret_generate`. Master secret could not be derived from handshake secret.                   |
| 0x0087 | `CTLS_STATUS_CRYPTO_EARLY_SECRET_RESET_FAILED`    | `ctls_key_schedule_operator_reset` failed before early secret extraction. Stale derivation operator could not be cleared.          |
| 0x0088 | `CTLS_STATUS_CRYPTO_EARLY_SECRET_SALT_ATTR_FAILED`  | `ctls_key_attributes_set(HKDF_EXTRACT)` failed when building salt key attributes for early secret.                               |
| 0x0089 | `CTLS_STATUS_CRYPTO_EARLY_SECRET_IKM_ATTR_FAILED`   | `ctls_key_attributes_set(HKDF_EXTRACT)` failed when building IKM key attributes for early secret.                               |
| 0x008A | `CTLS_STATUS_CRYPTO_EARLY_SECRET_SALT_IMPORT_FAILED` | `psa_import_key()` failed for the zero-salt key in `ctls_early_secret_generate`.                                                |
| 0x008B | `CTLS_STATUS_CRYPTO_EARLY_SECRET_IKM_IMPORT_FAILED`  | `psa_import_key()` failed for the zero-IKM key in `ctls_early_secret_generate`.                                                 |

### 0x008C–0x0096: Key schedule expand operations

| Code   | Name                                                  | Reason / Trigger                                                                                                                         |
|--------|-------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| 0x008C | `CTLS_STATUS_CRYPTO_KEY_ATTR_HKDF_BITS_FAILED`        | `ctls_key_bits_get` failed for HKDF key usage when setting attributes in `ctls_key_attributes_set`. Unknown hash algorithm.              |
| 0x008D | `CTLS_STATUS_CRYPTO_DERIVED_SECRET_EXPAND_FAILED`     | HKDF-Expand failed in `ctls_derived_secret_generate`. Derived secret (input to handshake secret extract) could not be produced.          |
| 0x008E | `CTLS_STATUS_CRYPTO_HS_TRAFFIC_SECRET_EXPAND_FAILED`  | HKDF-Expand failed in `ctls_handshake_traffic_secret_generate`. Client or server handshake traffic secret could not be derived.          |
| 0x008F | `CTLS_STATUS_CRYPTO_HS_WRITE_KEY_EXPAND_FAILED`       | HKDF-Expand failed in `ctls_handshake_write_key_generate`. Handshake write key could not be derived.                                     |
| 0x0090 | `CTLS_STATUS_CRYPTO_HS_IV_KEY_EXPAND_FAILED`          | HKDF-Expand failed in `ctls_handshake_iv_key_generate`. Handshake IV could not be derived.                                               |
| 0x0091 | `CTLS_STATUS_CRYPTO_HKDF_EXPAND_OP_FAILED`            | Low-level HKDF-Expand PSA operation failed inside `ctls_hkdf_expand`. One of setup/input_key/input_bytes/output_key returned non-success.|
| 0x0092 | `CTLS_STATUS_CRYPTO_FINISHED_KEY_EXPAND_FAILED`       | HKDF-Expand failed in `ctls_finished_key_generate`. Finished MAC key could not be derived from the handshake traffic secret.             |
| 0x0093 | `CTLS_STATUS_CRYPTO_APP_TRAFFIC_SECRET_EXPAND_FAILED` | HKDF-Expand failed in `ctls_application_traffic_secret_generate`. Application traffic secret could not be derived.                       |
| 0x0094 | `CTLS_STATUS_CRYPTO_EXPORTER_SECRET_EXPAND_FAILED`    | HKDF-Expand failed in `ctls_exporter_master_secret_generate`. Exporter master secret could not be derived.                               |
| 0x0095 | `CTLS_STATUS_CRYPTO_APP_WRITE_KEY_EXPAND_FAILED`      | HKDF-Expand failed in `ctls_application_write_key_generate`. Application write key could not be derived.                                 |
| 0x0096 | `CTLS_STATUS_CRYPTO_APP_IV_KEY_EXPAND_FAILED`         | HKDF-Expand failed in `ctls_application_iv_key_generate`. Application IV could not be derived.                                           |

### 0x0097–0x009C: HKDF-Extract internal sub-steps

| Code   | Name                                                   | Reason / Trigger                                                                                                                      |
|--------|--------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| 0x0097 | `CTLS_STATUS_CRYPTO_HKDF_EXTRACT_OUT_ATTR_FAILED`      | `ctls_key_attributes_set()` failed when building output key attributes for the extract PRK.                                           |
| 0x0098 | `CTLS_STATUS_CRYPTO_HKDF_EXTRACT_SETUP_FAILED`         | `psa_key_derivation_setup(PSA_ALG_HKDF)` failed inside `ctls_hkdf_extract`.                                                          |
| 0x0099 | `CTLS_STATUS_CRYPTO_HKDF_EXTRACT_SALT_EXPORT_FAILED`   | `psa_export_key()` of the salt PSA key failed in `ctls_hkdf_extract`.                                                                |
| 0x009A | `CTLS_STATUS_CRYPTO_HKDF_EXTRACT_SALT_INPUT_FAILED`    | `psa_key_derivation_input_bytes(SALT)` failed in `ctls_hkdf_extract`.                                                                |
| 0x009B | `CTLS_STATUS_CRYPTO_HKDF_EXTRACT_SECRET_INPUT_FAILED`  | `psa_key_derivation_input_key(SECRET)` failed in `ctls_hkdf_extract`.                                                                |
| 0x009C | `CTLS_STATUS_CRYPTO_HKDF_EXTRACT_OUTPUT_FAILED`        | `psa_key_derivation_output_key()` failed in `ctls_hkdf_extract`. PRK key handle could not be produced.                               |

### 0x009D–0x00A1: ECDHE key agreement

| Code   | Name                                              | Reason / Trigger                                                                                                                   |
|--------|---------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| 0x009D | `CTLS_STATUS_CRYPTO_KEY_ATTR_ECDH_BITS_FAILED`    | `ctls_key_bits_get` failed for ECDH key usage in `ctls_key_attributes_set`. Unknown ECC algorithm.                                |
| 0x009E | `CTLS_STATUS_CRYPTO_KEY_ATTR_SIGN_BITS_FAILED`    | `ctls_key_bits_get` failed for SIGN_MESSAGE key usage in `ctls_key_attributes_set`. Unknown signature algorithm.                  |
| 0x009F | `CTLS_STATUS_CRYPTO_KEY_ATTR_VERIFY_BITS_FAILED`  | `ctls_key_bits_get` failed for VERIFY_MESSAGE key usage in `ctls_key_attributes_set`. Unknown signature algorithm.                |
| 0x00A0 | `CTLS_STATUS_CRYPTO_RAW_KEY_AGREEMENT_FAILED`     | `psa_raw_key_agreement(PSA_ALG_ECDH)` failed in `ctls_ecdhe_shared_secret_generate`. Peer public key rejected or internal fault.  |
| 0x00A1 | `CTLS_STATUS_CRYPTO_SHARED_SECRET_IMPORT_FAILED`  | `psa_import_key()` failed when importing the raw ECDH shared secret bytes as a PSA key for HKDF input.                            |

### 0x00AA–0x00AD: Ephemeral and certificate key import/export

| Code   | Name                                              | Reason / Trigger                                                                                                                   |
|--------|---------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| 0x00AA | `CTLS_STATUS_CRYPTO_EPHEM_PUB_KEY_IMPORT_FAILED`  | `psa_import_key()` failed when importing the peer's ephemeral public key bytes for ECDH.                                          |
| 0x00AB | `CTLS_STATUS_CRYPTO_CERT_SPKI_NOT_FOUND`          | SPKI OID pattern not found in the DER certificate bytes during `ctls_certificate_private_key_import`. Malformed or wrong cert.    |
| 0x00AC | `CTLS_STATUS_CRYPTO_CERT_KEY_PAIR_IMPORT_FAILED`  | `psa_import_key()` failed when importing the private key from the PKCS#8 DER blob.                                                |
| 0x00AD | `CTLS_STATUS_CRYPTO_CERT_PUB_KEY_IMPORT_FAILED`   | `psa_import_key()` failed when importing the peer certificate's public key for signature verification.                             |

### 0x00B4–0x00B7: AEAD / nonce operations

| Code   | Name                                          | Reason / Trigger                                                                                                                   |
|--------|-----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| 0x00B4 | `CTLS_STATUS_CRYPTO_EPHEM_KEY_EXPORT_FAILED`  | `psa_export_public_key()` failed when exporting the local ephemeral public key to include in ClientHello/ServerHello key share.   |
| 0x00B5 | `CTLS_STATUS_CRYPTO_KEY_ATTR_AEAD_BITS_FAILED`| `ctls_key_bits_get` failed for AEAD key usage. Unknown cipher algorithm when building AEAD key attributes.                        |
| 0x00B6 | `CTLS_STATUS_CRYPTO_KEY_ATTR_HMAC_BITS_FAILED`| `ctls_key_bits_get` failed for HMAC key usage. Unknown hash algorithm when building HMAC key attributes.                          |
| 0x00B7 | `CTLS_STATUS_CRYPTO_NONCE_IV_EXPORT_FAILED`   | `psa_export_key()` failed when exporting the IV key bytes to XOR with the sequence number for a nonce. Key not yet derived.       |

### 0x00BC–0x00BE: Attribute and context-string guards

| Code   | Name                                                  | Reason / Trigger                                                                                                                         |
|--------|-------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| 0x00BC | `CTLS_STATUS_CRYPTO_KEY_BITS_UNKNOWN_ALG`             | `ctls_key_bits_get` switch hit the `default` case. A PSA algorithm ID has no registered bit-width mapping.                               |
| 0x00BD | `CTLS_STATUS_CRYPTO_KEY_ATTR_UNKNOWN_USAGE`           | `ctls_key_attributes_set` switch hit the `default` case. `CTLS_KEY_USAGE_*` value has no PSA attribute configuration.                   |
| 0x00BE | `CTLS_STATUS_CRYPTO_CONTEXT_STR_UNKNOWN_KEY_TYPE`     | `ctls_context_string_build` switch hit the `default` case. A `ctls_key_type_t` value has no HkdfLabel encoder.                           |

---

## 0x00C8–0x012B — Extension Serialization / Deserialization Errors

| Code   | Name                                      | Reason / Trigger                                                                                                                                                                                                                              |
|--------|-------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x00C8 | `CTLS_STATUS_EXTN_INVALID_SIZE_FLAG`         | `isOneByte` argument to `ctls_extn_enum_serialize/deserialize` is neither `CTLS_HELPER_IS_ONE_BYTE` nor `CTLS_HELPER_IS_TWO_BYTE`. Caller passed an uninitialized or wrong flag.                                                              |
| 0x00C9 | `CTLS_STATUS_EXTN_INVALID_FORM`              | `form` field is neither `CTLS_DATA_FORM_OPAQUE` nor `CTLS_DATA_FORM_PARSED`. Fired in `ctls_extn_server_name_serialize` and similar. Extension struct was never properly initialized.                                                         |
| 0x00CA | `CTLS_STATUS_EXTN_UNKNOWN_TYPE`              | Extension type value not handled in the `ctls_extn_is_initialized` switch. An extension type was added to the enum but the initialization check was not updated.                                                                              |
| 0x00CB | `CTLS_STATUS_EXTN_UNKNOWN_MSG_TYPE`          | `hsmg_type` passed to `ctls_extn_is_initialized` is not `CLIENT_HELLO`, `SERVER_HELLO`, `ENCRYPTED_EXTENSIONS`, or `CERTIFICATE_REQUEST`. Wrong message type used at call site.                                                               |
| 0x00CC | `CTLS_STATUS_EXTN_INVALID_STATUS_TYPE`       | Certificate status type is not `CTLS_EXTN_CERTIFICATE_STATUS_TYPE_OSCP`. Only OCSP is defined; any other value in the deserialized byte is a malformed or unsupported extension.                                                              |
| 0x00CD | `CTLS_STATUS_EXTN_INVALID_ENTITY_OWNERSHIP`  | `entity_ownership` in `ctls_extn_key_share_deserialize` is neither `CLIENT` nor `SERVER`. Caller passed uninitialized or wrong ownership flag.                                                                                                |
| 0x00CE | `CTLS_STATUS_EXTN_INVALID_WIRE_FORMAT`       | `wire_format` in any `_to_wire` extension function is not `DEFAULT` or `TRANSCRIPT_HASH`. Caller passed an unsupported format.                                                                                                                |
| 0x00CF | `CTLS_STATUS_EXTN_UNEXPECTED_EXPECTED_EXTNS` | `ctls_extn_encrypted_extensions_to_struct`: template's `encrypted_extension.expected_extensions` has non-zero count. No valid cTLS extensions for `EncryptedExtensions` exist in the expected-extensions list; this indicates a bad template. |
| 0x00D0 | `CTLS_STATUS_EXTN_INVALID_ENTITY`            | `entity` passed to an extension function is neither `CTLS_ENTITY_CLIENT` nor `CTLS_ENTITY_SERVER`. Caller used an uninitialized or wrong entity value. |

### 0x00D1–0x00D2: Enum size flags

| Code   | Name                                    | Reason / Trigger                                                                                                                               |
|--------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x00D1 | `CTLS_STATUS_EXTN_DESER_ENUM_SIZE_FLAG` | `ctls_extn_enum_deserialize`: `isOneByte` flag is not `CTLS_HELPER_IS_ONE_BYTE` or `CTLS_HELPER_IS_TWO_BYTE`. Caller passed invalid flag.      |
| 0x00D2 | `CTLS_STATUS_EXTN_SER_ENUM_SIZE_FLAG`   | `ctls_extn_enum_serialize`: `isOneByte` flag is not `CTLS_HELPER_IS_ONE_BYTE` or `CTLS_HELPER_IS_TWO_BYTE`. Caller passed invalid flag.        |

### 0x00D9–0x00DA: Extension form guards

| Code   | Name                                    | Reason / Trigger                                                                                                                         |
|--------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| 0x00D9 | `CTLS_STATUS_EXTN_ALPN_INVALID_FORM`    | `ctls_extn_alpn_serialize`: extension `form` is neither `CTLS_DATA_FORM_OPAQUE` nor `CTLS_DATA_FORM_PARSED`. Struct not initialized.    |
| 0x00DA | `CTLS_STATUS_EXTN_CERT_AUTH_INVALID_FORM` | `ctls_extn_certificate_authorities_serialize`: extension `form` is neither opaque nor parsed. Struct not initialized.                  |

### 0x00E1–0x00E8: Entity guards for crypto key schedule functions

| Code   | Name                                                   | Reason / Trigger                                                                                                                         |
|--------|--------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| 0x00E1 | `CTLS_STATUS_EXTN_CERT_STATUS_INVALID_ENTITY`          | `ctls_extn_certificate_status_to_struct`: `entity` not CLIENT/SERVER.                                                                    |
| 0x00E2 | `CTLS_STATUS_EXTN_CERT_CREATE_INVALID_ENTITY`          | `ctls_extn_certificate_to_struct` (create path): `entity` not CLIENT/SERVER.                                                             |
| 0x00E3 | `CTLS_STATUS_EXTN_HS_TRAFFIC_SECRET_INVALID_ENTITY`    | `ctls_handshake_traffic_secret_generate`: `entity` not CLIENT/SERVER.                                                                    |
| 0x00E4 | `CTLS_STATUS_EXTN_HS_WRITE_KEY_INVALID_ENTITY`         | `ctls_handshake_write_key_generate`: `entity` not CLIENT/SERVER.                                                                         |
| 0x00E5 | `CTLS_STATUS_EXTN_HS_IV_KEY_INVALID_ENTITY`            | `ctls_handshake_iv_key_generate`: `entity` not CLIENT/SERVER.                                                                            |
| 0x00E6 | `CTLS_STATUS_EXTN_APP_TRAFFIC_SECRET_INVALID_ENTITY`   | `ctls_application_traffic_secret_generate`: `entity` not CLIENT/SERVER.                                                                  |
| 0x00E7 | `CTLS_STATUS_EXTN_APP_WRITE_KEY_INVALID_ENTITY`        | `ctls_application_write_key_generate`: `entity` not CLIENT/SERVER.                                                                       |
| 0x00E8 | `CTLS_STATUS_EXTN_APP_IV_KEY_INVALID_ENTITY`           | `ctls_application_iv_key_generate`: `entity` not CLIENT/SERVER.                                                                          |

### 0x00F1–0x00F5: Wire-format guards per extension `_to_wire` function

| Code   | Name                                        | Reason / Trigger                                                                                       |
|--------|---------------------------------------------|--------------------------------------------------------------------------------------------------------|
| 0x00F1 | `CTLS_STATUS_EXTN_CH_INVALID_WIRE_FORMAT`   | `ctls_extn_client_hello_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                    |
| 0x00F2 | `CTLS_STATUS_EXTN_SH_INVALID_WIRE_FORMAT`   | `ctls_extn_server_hello_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                    |
| 0x00F3 | `CTLS_STATUS_EXTN_EE_INVALID_WIRE_FORMAT`   | `ctls_extn_encrypted_extensions_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.            |
| 0x00F4 | `CTLS_STATUS_EXTN_CR_INVALID_WIRE_FORMAT`   | `ctls_extn_certificate_request_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.             |
| 0x00F5 | `CTLS_STATUS_EXTN_CERT_INVALID_WIRE_FORMAT` | `ctls_extn_certificate_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                     |

---

## 0x012C–0x015D — Record Layer Errors

Sub-band layout:
```
0x012C–0x015D  Record Layer
  ├─ 0x012C–0x0133  Existing shared codes (preserved, never renumbered)
  ├─ 0x0134–0x013B  Header field violations (per call-site)
  ├─ 0x013C–0x0147  Message-type dispatch failures (per call-site; 0x0142–0x0147 reserved)
  ├─ 0x0148–0x0155  Wire-format guard, one code per _to_wire function (0x0151–0x0155 reserved)
  └─ 0x0156–0x015D  Entity / protocol violations (per call-site; 0x0159–0x015D reserved)
```

### 0x012C–0x0133: Existing shared codes (preserved)

| Code   | Name                                  | Reason / Trigger                                                                                                                                                                     |
|--------|---------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x012C | `CTLS_STATUS_RECD_UNSUPPORTED_CID`    | Legacy shared code — C bit set anywhere in the header path. Replaced by per-site codes below; kept for backward-compat.                                                              |
| 0x012D | `CTLS_STATUS_RECD_INVALID_SEQ_LEN`    | Legacy shared code — S bit outside {0,1} anywhere in the header path. Replaced by per-site codes below; kept for backward-compat.                                                   |
| 0x012E | `CTLS_STATUS_RECD_INVALID_CONTENT_TYPE` | Content type byte in the plaintext record header does not match any known `ctls_recd_content_type_t` value. Peer sent an unknown record type.                                      |
| 0x012F | `CTLS_STATUS_RECD_INVALID_WIRE_FORMAT`  | Legacy shared code — wire_format not DEFAULT/TRANSCRIPT_HASH in any `_to_wire` function. Replaced by per-function codes below; kept for backward-compat.                           |
| 0x0130 | `CTLS_STATUS_RECD_UNKNOWN_MSG_TYPE`     | Legacy shared code — unknown message type in serialize/deserialize dispatch. Replaced by per-site codes below; kept for backward-compat.                                            |
| 0x0131 | `CTLS_STATUS_RECD_NO_MUTUAL_AUTH`       | Legacy shared code — mutual_auth == 0 in `ctls_recd_certificate_request_to_struct`. Replaced by 0x0158; kept for backward-compat.                                                  |
| 0x0132 | `CTLS_STATUS_RECD_INVALID_MSG_TYPE`     | Legacy shared code — wrong message type in serialize dispatch. Replaced by per-site codes below; kept for backward-compat.                                                          |
| 0x0133 | `CTLS_STATUS_RECD_INVALID_ENTITY`       | Legacy shared code — entity not CLIENT/SERVER in create functions. Replaced by per-site codes below; kept for backward-compat.                                                      |

### 0x0134–0x013B: Header field violations

| Code   | Name                                    | Reason / Trigger                                                                                                                          |
|--------|-----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| 0x0134 | `CTLS_STATUS_RECD_AAD_LEN_CID`          | `ctls_aad_length_calculate`: `unified_header->config_octet.c_bit != 0`. CID not supported; fired before length calc.                     |
| 0x0135 | `CTLS_STATUS_RECD_HDR_SERIALIZE_CID`    | `ctls_unified_header_serialize`: `unified_header->config_octet.c_bit != 0`. CID present on a record being serialized.                    |
| 0x0136 | `CTLS_STATUS_RECD_HDR_SERIALIZE_SEQ`    | `ctls_unified_header_serialize`: `s_bit` not in {0, 1}. Struct was mutated after construction.                                           |
| 0x0137 | `CTLS_STATUS_RECD_HDR_DESERIALIZE_CID`  | `ctls_unified_header_deserialize`: parsed C bit = 1 from wire byte. Peer sent a CID-bearing record.                                      |
| 0x0138 | `CTLS_STATUS_RECD_HDR_DESERIALIZE_SEQ`  | `ctls_unified_header_deserialize`: parsed `s_bit > 1`. Wire header byte is malformed.                                                    |
| 0x0139 | `CTLS_STATUS_RECD_INVALID_AAD_LENGTH`   | Wire preprocess (`ctls_core_wire_preprocess`): parsed `unified_header.aad_length == 0` for an encrypted record. AAD is the unified header itself and can never be zero-length; peer sent a malformed header. |
| 0x013A | `CTLS_STATUS_RECD_EPOCH_MISMATCH`       | Wire preprocess: parsed header `epoch` (low 2 bits) does not match `hshk_data->epoch`. Record was encrypted under a different key generation than the one currently active (stale or replayed record). |
| 0x013B | `CTLS_STATUS_RECD_SEQUENCE_NUMBER_MISMATCH` | Wire preprocess: parsed header `sequence_number` does not equal `hshk_data->sequence_number`. Records arrived out of order or one was dropped/duplicated — cTLS uses a single shared counter incremented on every send/receive. |

### 0x013C–0x0147: Message-type dispatch failures

| Code   | Name                                       | Reason / Trigger                                                                                                                                                    |
|--------|--------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x013C | `CTLS_STATUS_RECD_SER_PLAIN_ENCRYPTED_MSG` | `ctls_record_serialize` plaintext branch: `message_type` is EE/CR/Cert/CV/Finished/Client-Flight/Server-Flight — these require encryption, not plain serialization. |
| 0x013D | `CTLS_STATUS_RECD_SER_PLAIN_UNKNOWN_MSG`   | `ctls_record_serialize` plaintext branch `default`: `message_type` has no registered plaintext serializer.                                                          |
| 0x013E | `CTLS_STATUS_RECD_SER_ENC_PLAINTEXT_MSG`   | `ctls_record_serialize` encrypted branch: `message_type` is EE/CR/Cert/CV/Finished — these are sub-messages, not top-level encrypted record types.                  |
| 0x013F | `CTLS_STATUS_RECD_SER_ENC_UNKNOWN_MSG`     | `ctls_record_serialize` encrypted branch `default`: `message_type` has no registered encrypted serializer.                                                          |
| 0x0140 | `CTLS_STATUS_RECD_DESER_STANDALONE_MSG`    | `ctls_record_deserialize`: caller passed a standalone HS message type (EE/CR/Cert/CV/Finished) that must be deserialized via sub-functions, not the top-level call.  |
| 0x0141 | `CTLS_STATUS_RECD_DESER_UNKNOWN_MSG`       | `ctls_record_deserialize` `default`: `hsmg_type` argument has no deserializer case registered.                                                                      |

### 0x0148–0x0155: Wire-format guard, per `_to_wire` function

| Code   | Name                                      | Reason / Trigger                                                                                                           |
|--------|-------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| 0x0148 | `CTLS_STATUS_RECD_CH_INVALID_WIRE_FORMAT`   | `ctls_recd_client_hello_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                                        |
| 0x0149 | `CTLS_STATUS_RECD_SH_INVALID_WIRE_FORMAT`   | `ctls_recd_server_hello_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                                        |
| 0x014A | `CTLS_STATUS_RECD_EE_INVALID_WIRE_FORMAT`   | `ctls_recd_encrypted_extensions_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                                |
| 0x014B | `CTLS_STATUS_RECD_CR_INVALID_WIRE_FORMAT`   | `ctls_recd_certificate_request_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                                 |
| 0x014C | `CTLS_STATUS_RECD_CERT_INVALID_WIRE_FORMAT` | `ctls_recd_certificate_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                                         |
| 0x014D | `CTLS_STATUS_RECD_CV_INVALID_WIRE_FORMAT`   | `ctls_recd_certificate_verify_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                                  |
| 0x014E | `CTLS_STATUS_RECD_FIN_INVALID_WIRE_FORMAT`  | `ctls_recd_finished_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                                            |
| 0x014F | `CTLS_STATUS_RECD_SF_INVALID_WIRE_FORMAT`   | `ctls_recd_server_flight_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                                       |
| 0x0150 | `CTLS_STATUS_RECD_CF_INVALID_WIRE_FORMAT`   | `ctls_recd_client_flight_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                                       |

### 0x0156–0x015D: Entity / protocol violations

| Code   | Name                                       | Reason / Trigger                                                                                                                                          |
|--------|--------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x0156 | `CTLS_STATUS_RECD_CV_CREATE_INVALID_ENTITY`  | `ctls_recd_certificate_verify_create`: `entity` is neither `CTLS_ENTITY_CLIENT` nor `CTLS_ENTITY_SERVER`.                                                |
| 0x0157 | `CTLS_STATUS_RECD_FIN_CREATE_INVALID_ENTITY` | `ctls_recd_finished_create`: `entity` is neither `CTLS_ENTITY_CLIENT` nor `CTLS_ENTITY_SERVER`.                                                          |
| 0x0158 | `CTLS_STATUS_RECD_CR_NO_MUTUAL_AUTH`         | `ctls_recd_certificate_request_to_struct`: `template->mutual_auth == 0`. CertificateRequest received on a non-mutual-auth profile; protocol violation.   |

---

## 0x015E–0x018F — Handshake Message Errors

| Code   | Name                                | Reason / Trigger                                                                                                                                                                                                                                         |
|--------|-------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x015E | `CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT` | Wire format passed to any `ctls_hsmg_*_to_wire` function is not `DEFAULT` or `TRANSCRIPT_HASH`.                                                                                                                                                          |
| 0x015F | `CTLS_STATUS_HSMG_UNKNOWN_MSG_TYPE`    | `ctls_transcript_hash_update`'s switch hit the default case; the record's `message_type` has no transcript-hash serializer. Fired for `NEW_SESSION_TICKET`, `KEY_UPDATE`, `SENTINEL`, etc. that should never appear during normal client-side handshake. |
| 0x0160 | `CTLS_STATUS_HSMG_INVALID_ENTITY`      | `entity` passed to a handshake-message function is neither `CTLS_ENTITY_CLIENT` nor `CTLS_ENTITY_SERVER`.                                                                                                                                                |
| 0x0161 | `CTLS_STATUS_HSMG_INVALID_MSG_TYPE` / `CTLS_STATUS_HSMG_CH_INVALID_WIRE_FORMAT` | **Duplicate value.** Both constants are assigned `0x0161` in `types.h`. `HSMG_INVALID_MSG_TYPE`: message type unrecognised in `hsmg` dispatch. `HSMG_CH_INVALID_WIRE_FORMAT`: `ctls_hsmg_client_hello_to_wire` wire_format guard. |

### 0x0162–0x0167: Wire-format guards per `ctls_hsmg_*_to_wire`

| Code   | Name                                        | Reason / Trigger                                                                                   |
|--------|---------------------------------------------|----------------------------------------------------------------------------------------------------|
| 0x0162 | `CTLS_STATUS_HSMG_SH_INVALID_WIRE_FORMAT`   | `ctls_hsmg_server_hello_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                |
| 0x0163 | `CTLS_STATUS_HSMG_EE_INVALID_WIRE_FORMAT`   | `ctls_hsmg_encrypted_extensions_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.        |
| 0x0164 | `CTLS_STATUS_HSMG_CR_INVALID_WIRE_FORMAT`   | `ctls_hsmg_certificate_request_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.         |
| 0x0165 | `CTLS_STATUS_HSMG_CERT_INVALID_WIRE_FORMAT` | `ctls_hsmg_certificate_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                 |
| 0x0166 | `CTLS_STATUS_HSMG_CV_INVALID_WIRE_FORMAT`   | `ctls_hsmg_certificate_verify_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.          |
| 0x0167 | `CTLS_STATUS_HSMG_FIN_INVALID_WIRE_FORMAT`  | `ctls_hsmg_finished_to_wire`: `wire_format` is not DEFAULT or TRANSCRIPT_HASH.                    |

---

## 0x0190–0x01C1 — Template / Profile Errors

| Code   | Name                                  | Reason / Trigger                                                                                                                                     |
|--------|---------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x0190 | `CTLS_STATUS_TMPL_NULL`                  | `ctls_validate_template` or any function that calls `ctls_template_get()` received NULL. Template was never set via `ctls_context_init`.             |
| 0x0191 | `CTLS_STATUS_TMPL_INVALID_CIPHER_SUITE`  | `template->cipher_suite` is 0 (sentinel). Profile must specify a cipher suite.                                                                       |
| 0x0192 | `CTLS_STATUS_TMPL_INVALID_DHE_GROUP`     | `template->dhe_group.dhe_group` is 0 (sentinel). Profile must specify a DHE group.                                                                   |
| 0x0193 | `CTLS_STATUS_TMPL_INVALID_SIG_ALGORITHM` | `template->signature_algorithm.signature_algorithm_type` is 0 (sentinel). Profile must specify a signature algorithm.                                |
| 0x0194 | `CTLS_STATUS_TMPL_UNKNOWN_PROFILE`       | `ctls_template_set` received a profile ID with no registered template. The `CTLS_PROFILE_ID` compile-time constant does not match any known profile. |
| 0x0195 | `CTLS_STATUS_TMPL_INVALID_EXTENSION`     | `ctls_tmpl_extension_to_wire`: `CTLS_EXTN_TYPE_KEY_SHARE` found in `expected_extensions` or `self_delimiting_extensions`. Key share is a runtime extension — must not appear in the template definition. |
| 0x0196 | `CTLS_STATUS_TMPL_UNKNOWN_ELEMENT`       | `ctls_template_element_to_wire` hit the `default` case — unrecognised `ctls_tmpl_type_t` value passed. New template element added to the enum without a serialization case. |
| 0x0197 | `CTLS_STATUS_TMPL_TO_WIRE_NULL`          | `ctls_template_to_wire` received a NULL output buffer. Called before the wire buffer was allocated.                                                                          |
| 0x0198 | `CTLS_STATUS_TMPL_EXTN_KEY_SHARE_IN_EXPECTED`     | `ctls_tmpl_extension_to_wire`: `CTLS_EXTN_TYPE_KEY_SHARE` found in `expected_extensions`. Key share is a runtime extension — must not appear in the template definition.  |
| 0x0199 | `CTLS_STATUS_TMPL_EXTN_KEY_SHARE_IN_SELF_DELIM`   | `ctls_tmpl_extension_to_wire`: `CTLS_EXTN_TYPE_KEY_SHARE` found in `self_delimiting_extensions`. Same constraint as above for the self-delimiting list.                   |

---

## 0x01C2–0x01F3 — Transport Errors

| Code   | Name                             | Reason / Trigger                                                                                                           |
|--------|----------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| 0x01C2 | `CTLS_STATUS_TRANSPORT_SEND_FAILED` | The `recd_send` callback returned non-success. The underlying socket/UART/bus write failed.                                |
| 0x01C3 | `CTLS_STATUS_TRANSPORT_RECV_FAILED` | The `recd_receive` callback returned non-success. No data arrived, the connection closed, or the driver reported an error. |

---

## 0x01F4–0x0225 — Handshake State Machine Errors

| Code   | Name                              | Reason / Trigger                                                                                                        |
|--------|-----------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| 0x01F4 | `CTLS_STATUS_HSHK_INVALID_STATE`     | An operation was attempted in a handshake state where it is not valid (e.g. trying to decrypt before keys are derived). |
| 0x01F5 | `CTLS_STATUS_HSHK_ALREADY_CONNECTED` | `ctls_connect` or `ctls_handshake` called when state is already `CTLS_HSHK_STATE_CONNECTED`.                            |

---

## 0x0226–0x0240 — Alert Mapping

One status code per `ctls_hsmg_alert_type_t` value (RFC 8446 §6.2), full 1:1 mirror of the alert enum.

**Why this band exists (bug 4 fix):** hooks previously called `ctls_alert_send` directly and returned its result, which could silently overwrite the original failure status. Under the new architecture, hooks return one of these `CTLS_STATUS_ALERT_*` codes instead of sending an alert themselves. The top-level handshake driver's `onerror` path calls `ctls_alert_send(record, status, entity, phase)`, which internally calls `ctls_status_to_alert_type_map` to map the code to its `ctls_hsmg_alert_type_t`, sends exactly one alert, then returns *status unchanged* — so the driver still returns the original `CTLS_STATUS_ALERT_*` code to the caller, not `CTLS_STATUS_SENT_ALERT` or a separate alert-send result.

Fatal/Warning level (RFC 8446 §6.2 — every alert is FATAL except `close_notify` and `user_canceled`, which are WARNING) is applied by `ctls_status_to_alert_type_map` at send time, not encoded in the status code itself.

| Code   | Name                                       | Maps to alert type                          |
|--------|---------------------------------------------|----------------------------------------------|
| 0x0226 | `CTLS_STATUS_ALERT_CLOSE_NOTIFY`            | `CTLS_HSMG_ALERT_TYPE_CLOSE_NOTIFY` (warning) |
| 0x0227 | `CTLS_STATUS_ALERT_UNEXPECTED_MESSAGE`      | `CTLS_HSMG_ALERT_TYPE_UNEXPECTED_MESSAGE`    |
| 0x0228 | `CTLS_STATUS_ALERT_BAD_RECORD_MAC`          | `CTLS_HSMG_ALERT_TYPE_BAD_RECORD_MAC`        |
| 0x0229 | `CTLS_STATUS_ALERT_RECORD_OVERFLOW`         | `CTLS_HSMG_ALERT_TYPE_RECORD_OVERFLOW`       |
| 0x022A | `CTLS_STATUS_ALERT_HANDSHAKE_FAILURE`       | `CTLS_HSMG_ALERT_TYPE_HANDSHAKE_FAILURE`     |
| 0x022B | `CTLS_STATUS_ALERT_BAD_CERTIFICATE`         | `CTLS_HSMG_ALERT_TYPE_BAD_CERTIFICATE`       |
| 0x022C | `CTLS_STATUS_ALERT_UNSUPPORTED_CERTIFICATE` | `CTLS_HSMG_ALERT_TYPE_UNSUPPORTED_CERTIFICATE` |
| 0x022D | `CTLS_STATUS_ALERT_CERTIFICATE_REVOKED`     | `CTLS_HSMG_ALERT_TYPE_CERTIFICATE_REVOKED`   |
| 0x022E | `CTLS_STATUS_ALERT_CERTIFICATE_EXPIRED`     | `CTLS_HSMG_ALERT_TYPE_CERTIFICATE_EXPIRED`   |
| 0x022F | `CTLS_STATUS_ALERT_CERTIFICATE_UNKNOWN`     | `CTLS_HSMG_ALERT_TYPE_CERTIFICATE_UNKNOWN`   |
| 0x0230 | `CTLS_STATUS_ALERT_ILLEGAL_PARAMETER`       | `CTLS_HSMG_ALERT_TYPE_ILLEGAL_PARAMETER`     |
| 0x0231 | `CTLS_STATUS_ALERT_UNKNOWN_CA`              | `CTLS_HSMG_ALERT_TYPE_UNKNOWN_CA`            |
| 0x0232 | `CTLS_STATUS_ALERT_ACCESS_DENIED`           | `CTLS_HSMG_ALERT_TYPE_ACCESS_DENIED`         |
| 0x0233 | `CTLS_STATUS_ALERT_DECODE_ERROR`            | `CTLS_HSMG_ALERT_TYPE_DECODE_ERROR`          |
| 0x0234 | `CTLS_STATUS_ALERT_DECRYPT_ERROR`           | `CTLS_HSMG_ALERT_TYPE_DECRYPT_ERROR`         |
| 0x0235 | `CTLS_STATUS_ALERT_PROTOCOL_VERSION`        | `CTLS_HSMG_ALERT_TYPE_PROTOCOL_VERSION`      |
| 0x0236 | `CTLS_STATUS_ALERT_INSUFFICIENT_SECURITY`   | `CTLS_HSMG_ALERT_TYPE_INSUFFICIENT_SECURITY` |
| 0x0237 | `CTLS_STATUS_ALERT_INTERNAL_ERROR`          | `CTLS_HSMG_ALERT_TYPE_INTERNAL_ERROR`        |
| 0x0238 | `CTLS_STATUS_ALERT_INAPPROPRIATE_FALLBACK`  | `CTLS_HSMG_ALERT_TYPE_INAPPROPRIATE_FALLBACK` |
| 0x0239 | `CTLS_STATUS_ALERT_USER_CANCELED`           | `CTLS_HSMG_ALERT_TYPE_USER_CANCELED` (warning) |
| 0x023A | `CTLS_STATUS_ALERT_MISSING_EXTENSION`       | `CTLS_HSMG_ALERT_TYPE_MISSING_EXTENSION`     |
| 0x023B | `CTLS_STATUS_ALERT_UNSUPPORTED_EXTENSION`   | `CTLS_HSMG_ALERT_TYPE_UNSUPPORTED_EXTENSION` |
| 0x023C | `CTLS_STATUS_ALERT_UNRECOGNIZED_NAME`       | `CTLS_HSMG_ALERT_TYPE_UNRECOGNIZED_NAME`     |
| 0x023D | `CTLS_STATUS_ALERT_BAD_CERTIFICATE_STATUS`  | `CTLS_HSMG_ALERT_TYPE_BAD_CERTIFICATE_STATUS` |
| 0x023E | `CTLS_STATUS_ALERT_UNKNOWN_PSK_IDENTITY`    | `CTLS_HSMG_ALERT_TYPE_UNKNOWN_PSK_IDENTITY`  |
| 0x023F | `CTLS_STATUS_ALERT_CERTIFICATE_REQUIRED`    | `CTLS_HSMG_ALERT_TYPE_CERTIFICATE_REQUIRED`  |
| 0x0240 | `CTLS_STATUS_ALERT_NO_APPLICATION_PROTOCOL` | `CTLS_HSMG_ALERT_TYPE_NO_APPLICATION_PROTOCOL` |

---

## Notes

### uint16_t vs uint8_t

`uint16_t` chosen because crypto alone needs ~15 codes and the full table is ~50.
`uint8_t` (max 255) would fit if ranges are compressed, but leaves no room for growth.

### What happens to `external_code`?

The raw PSA status is only useful for debug logging. Recommendation: store it in a
single `ctls_last_psa_status` global (or in `ctls_context_t`) before returning
`CTLS_STATUS_CRYPTO_*`. The error code itself tells you which subsystem and failure class.

### Existing `CTLS_CHECK_NULL` macro

Replace the single generic `CTLS_OP_STATUS_FAIL` return with context-specific codes:

- `buffer` or `offset` args → `CTLS_STATUS_NULL_BUFFER` / `CTLS_STATUS_NULL_OFFSET`
- primary struct arg (first param of most functions) → `CTLS_STATUS_NULL_STRUCT`
- global getter returns (template, crypto, hshk_data) → `CTLS_STATUS_TMPL_NULL` or `CTLS_STATUS_NULL_PTR`
