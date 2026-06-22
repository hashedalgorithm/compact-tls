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
| 0x0007 | `CTLS_STATUS_NOT_IMPLEMENTED` | Called a function stub (`ctls_hsmg_server_hello_create`, `ctls_hsmg_finished_*`, etc.) that has no body yet. Replaces silent empty returns that currently return garbage. |

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

---

## 0x012C–0x015D — Record Layer Errors

Sub-band layout:
```
0x012C–0x015D  Record Layer
  ├─ 0x012C–0x0133  Existing shared codes (preserved, never renumbered)
  ├─ 0x0134–0x013B  Header field violations (per call-site; 0x0139–0x013B reserved)
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
