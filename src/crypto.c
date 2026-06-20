/*
 * Crypto layer over PSA Crypto. See crypto.h for the key schedule diagram
 * (RFC 8446 §7.1 with cTLS "Sctls " labels) and per-function API docs.
 * Pattern used throughout: import key material as a transient PSA key,
 * run the operation, destroy the key and reset attributes in the cleanup
 * path — no raw secrets persist beyond hshk_data.
 */

#include <string.h>
#include "psa/crypto.h"
#include "ctls/types.h"
#include "ctls/ctls.h"
#include "ctls/bytes.h"
#include "ctls/templates.h"

psa_algorithm_t const CTLS_ECDHE_ALGORITHM = PSA_ALG_ECDH;
psa_algorithm_t const CTLS_GCM_ALGORITHM = PSA_ALG_GCM;

psa_algorithm_t const CTLS_CERTIFICATE_SIGNATURE_ALGORITHM = PSA_ALG_PURE_EDDSA;
psa_key_type_t const CTLS_CERTIFICATE_KEY_TYPE = PSA_ECC_FAMILY_TWISTED_EDWARDS;

uint8_t const SPKI_PATTERN[20] = {
    0x30,
    0x05,
    0x06,
    0x03,
    0x2b,
    0x65,
    0x70,
    0x03,
    0x21,
    0x00
};
size_t const SPKI_PATTERN_LENGTH = sizeof(SPKI_PATTERN);

ctls_status_t ctls_psa_error_map(psa_status_t const status) {
    switch (status) {
        case PSA_SUCCESS: return CTLS_STATUS_SUCCESS;
        case PSA_ERROR_INVALID_SIGNATURE: return CTLS_STATUS_CRYPTO_INVALID_SIGNATURE;
        case PSA_ERROR_BUFFER_TOO_SMALL: return CTLS_STATUS_BUFFER_TOO_SMALL;
        case PSA_ERROR_INVALID_ARGUMENT: return CTLS_STATUS_CRYPTO_INVALID_ARG;
        case PSA_ERROR_NOT_SUPPORTED: return CTLS_STATUS_CRYPTO_NOT_SUPPORTED;
        case PSA_ERROR_INSUFFICIENT_ENTROPY: return
                    CTLS_STATUS_CRYPTO_INSUFFICIENT_ENTROPY;
        default: return CTLS_STATUS_CRYPTO_UNKNOWN;
    }
}

ctls_status_t ctls_crypto_init() {
    ctls_template_t const *template = ctls_template_get();
    ctls_crypto_t *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(hshk_data);

    psa_status_t psa_result = psa_crypto_init();
    if (psa_result != PSA_SUCCESS) return CTLS_STATUS_CRYPTO_INIT_FAILED;

    ctls_status_t result = ctls_psa_hash_algorithm_set(crypto, template->cipher_suite);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_transcript_hash_init(crypto, hshk_data->transcript_hash, template);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hkdf_init(crypto, template->dhe_group.dhe_group);
}

ctls_status_t ctls_psa_hash_algorithm_set(ctls_crypto_t *crypto,
                                          ctls_cipher_suite_t const cipher_suite) {
    switch (cipher_suite) {
        case CTLS_HSMG_CIPHER_SUITE_AES_128_GCM_SHA256:
        case CTLS_HSMG_CIPHER_SUITE_AES_128_CCM_8_SHA256:
        case CTLS_HSMG_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
        case CTLS_HSMG_CIPHER_SUITE_AES_128_CCM_SHA256:
            crypto->hash_algorithm = PSA_ALG_SHA_256;
            break;
        case CTLS_HSMG_CIPHER_SUITE_AES_256_GCM_SHA384:
            crypto->hash_algorithm = PSA_ALG_SHA_384;
            break;
        default: return CTLS_STATUS_CRYPTO_UNSUPPORTED_CIPHER_SUITE;
    }
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_key_bits_get(psa_algorithm_t const *algorithm, ctls_size_t *key_bits) {
    CTLS_CHECK_NULL(algorithm);
    CTLS_CHECK_NULL(key_bits);

    switch (*algorithm) {
        case PSA_ALG_SHA_256: *key_bits = 256U;
            break;
        case PSA_ALG_SHA_384: *key_bits = 384U;
            break;
        case PSA_ALG_PURE_EDDSA:
        case PSA_ALG_ECDH: *key_bits = 255U;
            break;
        case PSA_ALG_GCM: *key_bits = 128U;
        default: return CTLS_STATUS_CRYPTO_INVALID_ARG;
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_psa_ecc_family_set(ctls_crypto_t *crypto,
                                      ctls_dhe_group_t const dhe_group_type) {
    switch (dhe_group_type) {
        case CTLS_EXTN_DHE_GROUP_FFDHE2048:
        case CTLS_EXTN_DHE_GROUP_FFDHE4096:
        case CTLS_EXTN_DHE_GROUP_FFDHE3072:
            crypto->ecdhe_key_pair_type = PSA_DH_FAMILY_RFC7919;
            break;
        case CTLS_EXTN_DHE_GROUP_SECP256R1:
        case CTLS_EXTN_DHE_GROUP_SECP384R1:
        case CTLS_EXTN_DHE_GROUP_SECP521R1:
            crypto->ecdhe_key_pair_type = PSA_ECC_FAMILY_SECP_R1;
            break;
        case CTLS_EXTN_DHE_GROUP_X448:
        case CTLS_EXTN_DHE_GROUP_X25519:
            crypto->ecdhe_key_pair_type = PSA_ECC_FAMILY_MONTGOMERY;
            break;
        default: return CTLS_STATUS_CRYPTO_UNSUPPORTED_DHE_GROUP;
    }
    return CTLS_STATUS_SUCCESS;
}

/*
 * Start the running transcript hash. The template's canonical wire bytes
 * are the first input — cTLS binds the profile into the transcript so
 * peers with different templates fail at Finished, not silently.
 * NOTE: transcript_hash doubles as scratch for the template bytes here.
 */
ctls_status_t ctls_transcript_hash_init(ctls_crypto_t *crypto,
                                        uint8_t *transcript_hash,
                                        ctls_template_t const *template) {
    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL(template);

    crypto->transcript_hash_operator = (psa_hash_operation_t) PSA_HASH_OPERATION_INIT;

    psa_status_t const result = psa_hash_setup(&crypto->transcript_hash_operator,
                                               crypto->hash_algorithm);
    if (result != PSA_SUCCESS) return CTLS_STATUS_CRYPTO_HASH_FAILED;

    ctls_status_t const res = ctls_template_to_wire(transcript_hash);
    if (res != CTLS_STATUS_SUCCESS) return res;

    return ctls_transcript_hash_calculate(&crypto->transcript_hash_operator,
                                          transcript_hash);
}

ctls_status_t ctls_transcript_hash_calculate(psa_hash_operation_t *hash_operator,
                                             uint8_t *transcript_hash) {
    CTLS_CHECK_NULL(hash_operator);
    CTLS_CHECK_NULL_BUFFER(transcript_hash);

    psa_status_t const result = psa_hash_update(hash_operator,
                                                transcript_hash,
                                                CTLS_SIZE_TRANSCRIPT_HASH);
    if (result != PSA_SUCCESS) return CTLS_STATUS_CRYPTO_HASH_FAILED;
    return CTLS_STATUS_SUCCESS;
}

/*
 * Absorb one handshake message into the transcript: serialize the record in
 * TRANSCRIPT_HASH wire format (reconstructed TLS 1.3 bytes, see
 * extensions.h) and feed it to the running hash. Called once per message
 * from the handshake driver, after send/receive.
 */
ctls_status_t ctls_transcript_hash_update(ctls_record_t const *record) {
    ctls_crypto_t *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t offset = 0;

    switch (record->record_body.message_type) {
        case CTLS_HSMG_TYPE_CLIENT_HELLO:
            ctls_recd_client_hello_to_wire(buffer,
                                           &offset,
                                           record,
                                           CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        case CTLS_HSMG_TYPE_SERVER_HELLO:
            ctls_recd_server_hello_to_wire(buffer,
                                           &offset,
                                           record,
                                           CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS:
            ctls_recd_encrypted_extensions_to_wire(buffer,
                                                   &offset,
                                                   record,
                                                   CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        case CTLS_HSMG_TYPE_CERTIFICATE_REQUEST:
            ctls_recd_certificate_request_to_wire(buffer,
                                                  &offset,
                                                  record,
                                                  CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        case CTLS_HSMG_TYPE_CERTIFICATE:
            ctls_recd_certificate_to_wire(buffer,
                                          &offset,
                                          record,
                                          CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        case CTLS_HSMG_TYPE_CERTIFICATE_VERIFY:
            ctls_recd_certificate_verify_to_wire(buffer,
                                                 &offset,
                                                 record,
                                                 CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        case CTLS_HSMG_TYPE_FINISHED:
            ctls_recd_finished_to_wire(buffer,
                                       &offset,
                                       record,
                                       CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        case CTLS_HSMG_TYPE_NEW_SESSION_TICKET:
        case CTLS_HSMG_TYPE_END_OF_EARLY_DATA:
        case CTLS_HSMG_TYPE_HELLO_RETRY_REQUEST:
        case CTLS_HSMG_TYPE_KEY_UPDATE:
        case CTLS_HSMG_TYPE_MESSAGE_HASH:
        case CTLS_HSMG_TYPE_SENTINEL: default: return CTLS_STATUS_HSMG_UNKNOWN_MSG_TYPE;
    }

    return ctls_transcript_hash_calculate(&crypto->transcript_hash_operator,
                                          hshk_data->transcript_hash);
}

/*
 * Read the current Transcript-Hash without killing the running operator:
 * psa_hash_clone, finish the clone. Needed because the key schedule and
 * CertificateVerify consume intermediate transcript values mid-handshake.
 */
ctls_status_t transcript_snapshot(psa_hash_operation_t const *hash_operator,
                                  uint8_t *buffer) {
    psa_hash_operation_t clone = PSA_HASH_OPERATION_INIT;

    psa_status_t result = psa_hash_clone(hash_operator, &clone);
    if (result != PSA_SUCCESS) return CTLS_STATUS_CRYPTO_HASH_FAILED;

    size_t out_len;
    result = psa_hash_finish(&clone, buffer, CTLS_SIZE_TRANSCRIPT_HASH, &out_len);
    if (result != PSA_SUCCESS) return CTLS_STATUS_CRYPTO_HASH_FAILED;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_hkdf_init(ctls_crypto_t *crypto,
                             ctls_dhe_group_t const ecdhe_group_type) {
    CTLS_CHECK_NULL_STRUCT(crypto);

    ctls_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_psa_ecc_family_set(crypto, ecdhe_group_type);
}

ctls_status_t ctls_key_schedule_operator_reset(ctls_crypto_t *crypto) {
    CTLS_CHECK_NULL_STRUCT(crypto);

    crypto->key_schedule_operator = (psa_key_derivation_operation_t)
            PSA_KEY_DERIVATION_OPERATION_INIT;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_ephemeral_public_key_import(uint8_t const *buffer,
                                               ctls_size_t const buffer_length,
                                               psa_key_id_t *ephemeral_public_key) {
    ctls_crypto_t const *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL(buffer);

    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t server_public_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    *ephemeral_public_key = PSA_KEY_ID_NULL;

    ctls_status_t const result =
            ctls_key_attributes_set(CTLS_KEY_USAGE_EPHEMERAL_PUBLIC_KEY_EXPORT,
                                    &server_public_key_attributes);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    psa_st = psa_import_key(&server_public_key_attributes,
                            buffer,
                            buffer_length,
                            ephemeral_public_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;

cleanup:
    psa_reset_key_attributes(&server_public_key_attributes);
    return CTLS_STATUS_CRYPTO_KEY_IMPORT_FAILED;
}

ctls_status_t ctls_ephemeral_public_key_export(psa_key_id_t const *ephemeral_key_pair_id,
                                               uint8_t *buffer,
                                               ctls_size_t const buffer_length,
                                               ctls_size_t *buffer_bytes_written) {
    CTLS_CHECK_NULL_KEY_ID(ephemeral_key_pair_id);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(buffer_bytes_written);

    size_t offset;
    psa_status_t const psa_st = psa_export_public_key(*ephemeral_key_pair_id,
                                                      buffer,
                                                      buffer_length,
                                                      &offset);
    *buffer_bytes_written = offset;
    if (psa_st != PSA_SUCCESS) return CTLS_STATUS_CRYPTO_KEY_EXPORT_FAILED;

    return psa_st;
}

ctls_status_t ctls_ephemeral_key_pair_generate(psa_key_id_t *ephemeral_key_pair_id) {
    ctls_crypto_t const *crypto = ctls_crypto_get();
    CTLS_CHECK_NULL(crypto);

    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t ephemeral_key_pair_attributes = PSA_KEY_ATTRIBUTES_INIT;
    *ephemeral_key_pair_id = PSA_KEY_ID_NULL;

    ctls_status_t const result =
            ctls_key_attributes_set(CTLS_KEY_USAGE_EPHEMERAL_KEY_PAIR_GENERATE,
                                    &ephemeral_key_pair_attributes);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;


    psa_st = psa_generate_key(&ephemeral_key_pair_attributes, ephemeral_key_pair_id);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;

cleanup:
    psa_reset_key_attributes(&ephemeral_key_pair_attributes);
    return CTLS_STATUS_CRYPTO_KEY_GEN_FAILED;
}

ctls_status_t ctls_random_generate(uint8_t *buffer,
                                   ctls_size_t *bytes_written,
                                   uint8_t const random_size) {
    psa_status_t const result = psa_generate_random(buffer, random_size);
    *bytes_written = random_size;
    if (result != PSA_SUCCESS) return CTLS_STATUS_CRYPTO_RANDOM_FAILED;
    return CTLS_STATUS_SUCCESS;
}

/*
 * Full key schedule run (crypto.h diagram), called once after ServerHello:
 * early secret -> derived secret -> ECDHE -> handshake secret -> client +
 * server traffic secrets -> AEAD keys + IVs. Ends by bumping the epoch to
 * 2 (handshake keys, RFC 9147 §6.1 — epoch 1 / early data unsupported).
 */
ctls_status_t ctls_key_schedule() {
    ctls_crypto_t *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL(hshk_data);

    ctls_status_t result = ctls_early_secret_generate(crypto);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_derived_secret_generate(crypto);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_shared_ephemeral_secret_generate(crypto);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_handshake_secret_generate(crypto);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_handshake_traffic_secret_generate(crypto, CTLS_ENTITY_CLIENT);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_handshake_traffic_secret_generate(crypto, CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_handshake_write_key_generate(crypto, CTLS_ENTITY_CLIENT);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_handshake_write_key_generate(crypto, CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_handshake_iv_key_generate(crypto, CTLS_ENTITY_CLIENT);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_handshake_iv_key_generate(crypto, CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    /* Keys switched to handshake traffic keys — new epoch. RFC 9147 §6.1
       numbering: epoch 0 plaintext, 1 early data (unsupported, skipped),
       2 handshake keys. */
    result = ctls_epoch_counter_increment();
    if (result != CTLS_STATUS_SUCCESS) return result;
    return ctls_epoch_counter_increment();
}

ctls_status_t ctls_key_attributes_set(ctls_key_usage_t const key_usage,
                                      psa_key_attributes_t *key_attribute) {
    ctls_crypto_t const *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL(key_attribute);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint16_t key_bits;

    switch (key_usage) {
        case CTLS_KEY_USAGE_EPHEMERAL_KEY_PAIR_GENERATE:
        case CTLS_KEY_USAGE_EPHEMERAL_PUBLIC_KEY_EXPORT: {
            psa_set_key_type(key_attribute,
                             key_usage == CTLS_KEY_USAGE_EPHEMERAL_PUBLIC_KEY_EXPORT
                                 ? PSA_KEY_TYPE_ECC_PUBLIC_KEY(crypto->
                                  ecdhe_key_pair_type)
                                 : PSA_KEY_TYPE_ECC_KEY_PAIR(crypto->
                                  ecdhe_key_pair_type));
            psa_set_key_usage_flags(key_attribute,
                                    PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
            psa_set_key_algorithm(key_attribute, CTLS_ECDHE_ALGORITHM);

            result = ctls_key_bits_get(&CTLS_ECDHE_ALGORITHM, &key_bits);
            if (result != CTLS_STATUS_SUCCESS) return CTLS_STATUS_CRYPTO_ECDH_FAILED;
            psa_set_key_bits(key_attribute, key_bits);
        }
        break;
        case CTLS_KEY_USAGE_HKDF_EXTRACT:
        case CTLS_KEY_USAGE_HKDF_EXPAND: {
            psa_set_key_type(key_attribute, PSA_KEY_TYPE_DERIVE);
            psa_set_key_usage_flags(key_attribute,
                                    PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
            psa_set_key_algorithm(key_attribute,
                                  key_usage == CTLS_KEY_USAGE_HKDF_EXTRACT
                                      ? PSA_ALG_HKDF_EXTRACT(crypto->hash_algorithm)
                                      : PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
            result = ctls_key_bits_get(&crypto->hash_algorithm, &key_bits);
            if (result != CTLS_STATUS_SUCCESS)
                return CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED;
            psa_set_key_bits(key_attribute, key_bits);
        }
        break;
        case CTLS_KEY_USAGE_AEAD_ENCRYPT_OR_DECRYPT: {
            psa_set_key_type(key_attribute, PSA_KEY_TYPE_AES);
            psa_set_key_usage_flags(key_attribute,
                                    PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
            psa_set_key_algorithm(key_attribute, CTLS_GCM_ALGORITHM);
            result = ctls_key_bits_get(&CTLS_GCM_ALGORITHM, &key_bits);
            if (result != CTLS_STATUS_SUCCESS)
                return CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED;
            psa_set_key_bits(key_attribute, key_bits);
        }
        break;
        case CTLS_KEY_USAGE_HMAC: {
            psa_set_key_type(key_attribute, PSA_KEY_TYPE_HMAC);
            psa_set_key_usage_flags(key_attribute,
                                    PSA_KEY_USAGE_SIGN_MESSAGE |
                                    PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT);
            psa_set_key_algorithm(key_attribute, PSA_ALG_HMAC(crypto->hash_algorithm));
            result = ctls_key_bits_get(&crypto->hash_algorithm, &key_bits);
            if (result != CTLS_STATUS_SUCCESS)
                return CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED;
            psa_set_key_bits(key_attribute, key_bits);
        }
        break;
        case CTLS_KEY_USAGE_SIGN_MESSAGE: {
            psa_set_key_type(key_attribute,
                             PSA_KEY_TYPE_ECC_KEY_PAIR(CTLS_CERTIFICATE_KEY_TYPE));
            psa_set_key_usage_flags(key_attribute,
                                    PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
            psa_set_key_algorithm(key_attribute, CTLS_CERTIFICATE_SIGNATURE_ALGORITHM);

            result = ctls_key_bits_get(&CTLS_CERTIFICATE_SIGNATURE_ALGORITHM, &key_bits);
            if (result != CTLS_STATUS_SUCCESS) return CTLS_STATUS_CRYPTO_ECDH_FAILED;
            psa_set_key_bits(key_attribute, key_bits);
        }
        break;
        case CTLS_KEY_USAGE_VERIFY_SIGNATURE: {
            psa_set_key_type(key_attribute,
                             PSA_KEY_TYPE_ECC_PUBLIC_KEY(CTLS_CERTIFICATE_KEY_TYPE));
            psa_set_key_usage_flags(key_attribute,
                                    PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT);
            psa_set_key_algorithm(key_attribute, CTLS_CERTIFICATE_SIGNATURE_ALGORITHM);

            result = ctls_key_bits_get(&CTLS_CERTIFICATE_SIGNATURE_ALGORITHM, &key_bits);
            if (result != CTLS_STATUS_SUCCESS) return CTLS_STATUS_CRYPTO_ECDH_FAILED;
            psa_set_key_bits(key_attribute, key_bits);
        }
        break;
        default: return CTLS_STATUS_CRYPTO_INVALID_ARG;
    }
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_context_string_build(uint8_t *buffer,
                                        ctls_size_t *offset,
                                        ctls_entity_t const entity,
                                        ctls_key_type_t const key_type) {
    /*
     * HkdfLabel encoding (RFC 8446 §7.1), label prefix "Sctls " per the
     * cTLS profile instead of "tls13 ":
     *
     *     output_length(u16) | label_length(u8) | label bytes
     *     | context_length(u8) | context bytes
     *
     * SIGNED_BYTES is the odd one out — it emits the RFC 8446 §4.4.3
     * signing content instead: 64 x 0x20 | context string | 0x00 |
     * transcript hash.
     */

    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(offset);
    CTLS_CHECK_NULL_STRUCT(hshk_data);
    CTLS_CHECK_NULL_BUFFER(hshk_data->transcript_hash);

    char const *context_string = NULL;
    uint8_t context_string_length = 0;

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER) return
            CTLS_STATUS_CRYPTO_INVALID_ARG;

    switch (key_type) {
        case CTLS_KEY_TYPE_DERIVED_SECRET: {
            /*
             *Label prefix: "Sctls " (cTLS draft-10 §6)
             * HkdfLabel encoding:
             *   uint16 length       = 32
             *   uint8  label_len    = len("Sctls derived")
             *   bytes  label        = "Sctls derived"
             *   uint8  context_len  = 32
             *   bytes  context      = H("")
             */
            context_string = "Sctls derived";
            context_string_length = strlen(context_string) - 1U;

            ctls_write_u16(buffer, offset, 0x00);
            ctls_write_u8(buffer, offset, 0x20);
            ctls_write_u8(buffer, offset, context_string_length);
            ctls_write_char_bytes(buffer, offset, context_string_length, context_string);
            ctls_write_u8(buffer, offset, 0x20);
            ctls_write_bytes(buffer, offset, 32U, hshk_data->transcript_hash);
        }
        break;
        case CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_SECRET: {
            if (entity == CTLS_ENTITY_CLIENT) {
                context_string = "Sctls c hs traffic";
                context_string_length = strlen(context_string) - 1U;
            } else {
                context_string = "Sctls s hs traffic";
                context_string_length = strlen(context_string) - 1U;
            }
            ctls_write_u16(buffer, offset, 0x00);
            ctls_write_u8(buffer, offset, 0x20);
            ctls_write_u8(buffer, offset, context_string_length);
            ctls_write_char_bytes(buffer, offset, context_string_length, context_string);
            ctls_write_u8(buffer, offset, CTLS_SIZE_HASH);
            ctls_write_bytes(buffer, offset, CTLS_SIZE_HASH, hshk_data->transcript_hash);
        }
        break;
        case CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_WRITE_KEYS: {
            context_string = "Sctls key";
            context_string_length = strlen(context_string) - 1U;


            ctls_write_u16(buffer, offset, 0x00);
            ctls_write_u8(buffer, offset, 0x10);
            ctls_write_u8(buffer, offset, context_string_length);
            ctls_write_char_bytes(buffer, offset, context_string_length, context_string);
            ctls_write_u8(buffer, offset, 0x00);
        }
        break;
        case CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_IV_KEY: {
            context_string = "Sctls iv";
            context_string_length = strlen(context_string) - 1U;

            ctls_write_u16(buffer, offset, 0x00);
            ctls_write_u8(buffer, offset, 0x0C);
            ctls_write_u8(buffer, offset, context_string_length);
            ctls_write_char_bytes(buffer, offset, context_string_length, context_string);
            ctls_write_u8(buffer, offset, 0x00);
        }
        break;
        case CTLS_KEY_TYPE_SIGNED_BYTES: {
            if (entity == CTLS_ENTITY_CLIENT) {
                context_string = "TLS 1.3, client CertificateVerify";
                context_string_length = strlen(context_string) - 1U;
            } else {
                context_string = "TLS 1.3, server CertificateVerify";
                context_string_length = strlen(context_string) - 1U;
            }

            memset(buffer, 0x20, 64U);
            offset += 64U;
            ctls_write_bytes(buffer,
                             offset,
                             context_string_length,
                             (uint8_t *) context_string);
            ctls_write_u8(buffer, offset, 0x00);
            ctls_write_bytes(buffer,
                             offset,
                             CTLS_SIZE_TRANSCRIPT_HASH,
                             hshk_data->transcript_hash);
        }
        break;
        case CTLS_KEY_TYPE_FINISHED_KEY: {
            context_string = "Sctls finished";
            context_string_length = strlen(context_string) - 1U;

            ctls_write_u16(buffer, offset, 0x00);
            ctls_write_u8(buffer, offset, 0x00);
            ctls_write_u16(buffer, offset, context_string_length);
            ctls_write_char_bytes(buffer, offset, context_string_length, context_string);
            ctls_write_u8(buffer, offset, 0x00);
        }
        break;
        case CTLS_KEY_TYPE_BINDER_KEY: {
            context_string = "Sctls res binder";
            context_string_length = strlen(context_string) - 1U;

            ctls_write_u16(buffer, offset, 0x00);
            ctls_write_u8(buffer, offset, 0x20);
            ctls_write_u8(buffer, offset, context_string_length);
            ctls_write_char_bytes(buffer, offset, context_string_length, context_string);
            ctls_write_u8(buffer, offset, 0x00);
        }
        break;
        case CTLS_KEY_TYPE_CLIENT_EARLY_KEY: {
            context_string = "Sctls c e traffic";
            context_string_length = strlen(context_string) - 1U;

            ctls_write_u16(buffer, offset, 0x00);
            ctls_write_u8(buffer, offset, 0x20);
            ctls_write_u8(buffer, offset, context_string_length);
            ctls_write_char_bytes(buffer, offset, context_string_length, context_string);
            ctls_write_u8(buffer, offset, CTLS_SIZE_HASH);
            ctls_write_bytes(buffer, offset, CTLS_SIZE_HASH, hshk_data->transcript_hash);
        }
        break;
        case CTLS_KEY_TYPE_EXPORTER_MASTER_SECRET: {
            context_string = "Sctls exp master";
            context_string_length = strlen(context_string) - 1U;

            ctls_write_u16(buffer, offset, 0x00);
            ctls_write_u8(buffer, offset, 0x20);
            ctls_write_u8(buffer, offset, context_string_length);
            ctls_write_char_bytes(buffer, offset, context_string_length, context_string);
            ctls_write_u8(buffer, offset, CTLS_SIZE_HASH);
            ctls_write_bytes(buffer, offset, CTLS_SIZE_HASH, hshk_data->transcript_hash);
        }
        break;
        case CTLS_KEY_TYPE_APPLICATION_TRAFFIC_SECRET: {
            if (entity == CTLS_ENTITY_CLIENT) {
                context_string = "Sctls c ap traffic";
                context_string_length = strlen(context_string) - 1U;
            } else {
                context_string = "Sctls s ap traffic";
                context_string_length = strlen(context_string) - 1U;
            }
            ctls_write_u16(buffer, offset, 0x00);
            ctls_write_u8(buffer, offset, 0x20);
            ctls_write_u8(buffer, offset, context_string_length);
            ctls_write_char_bytes(buffer, offset, context_string_length, context_string);
            ctls_write_u8(buffer, offset, CTLS_SIZE_HASH);
            ctls_write_bytes(buffer, offset, CTLS_SIZE_HASH, hshk_data->transcript_hash);
        }
        break;
        case CTLS_KEY_TYPE_APPLICATION_TRAFFIC_WRITE_KEYS: {
            context_string = "Sctls key";
            context_string_length = strlen(context_string) - 1U;

            ctls_write_u16(buffer, offset, 0x00);
            ctls_write_u8(buffer, offset, 0x10);
            ctls_write_u8(buffer, offset, context_string_length);
            ctls_write_char_bytes(buffer, offset, context_string_length, context_string);
            ctls_write_u8(buffer, offset, 0x00);
        }
        break;
        break;
        default: return CTLS_STATUS_CRYPTO_INVALID_ARG;
    }

    return CTLS_STATUS_SUCCESS;
}


/*
 * early_secret = HKDF-Extract(salt = 0, ikm = 0) — RFC 8446 §7.1, no-PSK
 * profile, so both inputs are 32 zero bytes.
 */
ctls_status_t ctls_early_secret_generate(ctls_crypto_t *crypto) {
    CTLS_CHECK_NULL_STRUCT(crypto);

    static const uint8_t ZEROS[32] = {0};
    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t salt_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t salt = PSA_KEY_ID_NULL;
    psa_key_attributes_t ikm_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t ikm = PSA_KEY_ID_NULL;

    ctls_status_t result = ctls_key_schedule_operator_reset(crypto);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    result = ctls_key_attributes_set(CTLS_KEY_USAGE_HKDF_EXTRACT, &salt_attributes);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    result = ctls_key_attributes_set(CTLS_KEY_USAGE_HKDF_EXTRACT, &ikm_attributes);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    psa_st = psa_import_key(&salt_attributes, ZEROS, CTLS_SIZE_HASH, &salt);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_import_key(&ikm_attributes, ZEROS, CTLS_SIZE_HASH, &ikm);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    result = ctls_hkdf_extract(&crypto->early_secret, &salt, &ikm);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;
cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    if (ikm != PSA_KEY_ID_NULL) { psa_destroy_key(ikm); }
    if (salt != PSA_KEY_ID_NULL) { psa_destroy_key(salt); }
    psa_reset_key_attributes(&salt_attributes);
    psa_reset_key_attributes(&ikm_attributes);

    return CTLS_STATUS_CRYPTO_HKDF_EXTRACT_FAILED;
}


ctls_status_t ctls_derived_secret_generate(ctls_crypto_t *crypto) {
    CTLS_CHECK_NULL_STRUCT(crypto);

    uint8_t info[80U];
    ctls_size_t offset = 0U;

    ctls_status_t result = ctls_context_string_build(info,
                                                     &offset,
                                                     CTLS_ENTITY_CLIENT,
                                                     CTLS_KEY_TYPE_DERIVED_SECRET);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    result = ctls_hkdf_expand(&crypto->derived_secret,
                              &crypto->shared_ephemeral_secret,
                              CTLS_KEY_USAGE_HKDF_EXPAND,
                              info,
                              offset);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;
    return CTLS_STATUS_SUCCESS;
cleanup:
    return CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED;
}


ctls_status_t ctls_shared_ephemeral_secret_generate(ctls_crypto_t *crypto) {
    CTLS_CHECK_NULL_STRUCT(crypto);

    psa_status_t psa_st = PSA_SUCCESS;
    uint8_t peer_public_ephemeral_key[CTLS_SIZE_KEY_SHARE];
    uint8_t shared_ephemeral_secret[CTLS_SIZE_KEY_SHARE];
    ctls_size_t peer_public_ephemeral_key_offset = 0;
    size_t shared_ephemeral_secret_length = 0;

    ctls_status_t result = ctls_ephemeral_public_key_export(&crypto->
                                                                peer_public_ephemeral_key,
                                                                peer_public_ephemeral_key,
                                                                CTLS_SIZE_KEY_SHARE,
                                                                &peer_public_ephemeral_key_offset);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    psa_st = psa_raw_key_agreement(CTLS_ECDHE_ALGORITHM,
                                   crypto->self_ephemeral_key_pair,
                                   peer_public_ephemeral_key,
                                   CTLS_SIZE_KEY_SHARE,
                                   shared_ephemeral_secret,
                                   CTLS_SIZE_KEY_SHARE,
                                   &shared_ephemeral_secret_length);
    if (psa_st != PSA_SUCCESS) return CTLS_STATUS_CRYPTO_ECDH_FAILED;

    crypto->shared_ephemeral_secret = PSA_KEY_ID_NULL;
    psa_key_attributes_t shared_ephemeral_secret_attribute = PSA_KEY_ATTRIBUTES_INIT;
    result = ctls_key_attributes_set(CTLS_KEY_USAGE_EPHEMERAL_KEY_PAIR_GENERATE,
                                     &shared_ephemeral_secret_attribute);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    psa_st = psa_import_key(&shared_ephemeral_secret_attribute,
                            shared_ephemeral_secret,
                            CTLS_SIZE_KEY_SHARE,
                            &crypto->shared_ephemeral_secret);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    memset(shared_ephemeral_secret, 0, CTLS_SIZE_KEY_SHARE);
    memset(peer_public_ephemeral_key, 0, CTLS_SIZE_KEY_SHARE);
    return CTLS_STATUS_SUCCESS;

cleanup:
    return CTLS_STATUS_CRYPTO_ECDH_FAILED;
}

/*
 * handshake_secret = HKDF-Extract(salt = derived_secret,
 *                                 ikm = ECDHE shared secret) — RFC 8446 §7.1.
 */
ctls_status_t ctls_handshake_secret_generate(ctls_crypto_t *crypto) {
    CTLS_CHECK_NULL_STRUCT(crypto);

    return ctls_hkdf_extract(&crypto->handshake_secret,
                             &crypto->derived_secret,
                             &crypto->shared_ephemeral_secret);
}

/*
 * c/s hs traffic secret = Expand-Label(handshake_secret,
 *     "c hs traffic" | "s hs traffic", Transcript-Hash(CH..SH), 32)
 * — RFC 8446 §7.1; entity picks label and output slot.
 */
ctls_status_t ctls_handshake_traffic_secret_generate(ctls_crypto_t *crypto,
                                                     ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(crypto);
    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_EXTN_INVALID_ENTITY;

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t info[80U];
    ctls_size_t info_offset = 0U;

    result = ctls_context_string_build(info,
                                       &info_offset,
                                       entity,
                                       CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_SECRET);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;


    return ctls_hkdf_expand(entity == CTLS_ENTITY_CLIENT
                                ? &crypto->client_handshake_traffic_secret
                                : &crypto->server_handshake_traffic_secret,
                            &crypto->handshake_secret,
                            CTLS_KEY_USAGE_HKDF_EXPAND,
                            info,
                            info_offset);

cleanup:
    return CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED;
}

/*
 * AEAD write key = Expand-Label(traffic_secret, "key", "", 16)
 * — RFC 8446 §7.3.
 */
ctls_status_t ctls_handshake_write_key_generate(ctls_crypto_t *crypto,
                                                ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(crypto);
    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_EXTN_INVALID_ENTITY;

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t info[32U];
    ctls_size_t info_offset = 0U;

    result = ctls_context_string_build(info,
                                       &info_offset,
                                       entity,
                                       CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_WRITE_KEYS);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    return ctls_hkdf_expand(entity == CTLS_ENTITY_CLIENT
                                ? &crypto->client_handshake_write_key
                                : &crypto->server_handshake_write_key,
                            entity == CTLS_ENTITY_CLIENT
                                ? &crypto->client_handshake_traffic_secret
                                : &crypto->server_handshake_traffic_secret,
                            CTLS_KEY_USAGE_AEAD_ENCRYPT_OR_DECRYPT,
                            info,
                            info_offset);
cleanup:
    return CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED;
}

/*
 * Static record IV = Expand-Label(traffic_secret, "iv", "", 12)
 * — RFC 8446 §7.3; XORed with the sequence number per record
 * (ctls_nonce_generate).
 */
ctls_status_t ctls_handshake_iv_key_generate(ctls_crypto_t *crypto,
                                             ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(crypto);
    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_EXTN_INVALID_ENTITY;

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t info[32U];
    ctls_size_t info_offset = 0U;

    result = ctls_context_string_build(info,
                                       &info_offset,
                                       entity,
                                       CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_IV_KEY);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    return ctls_hkdf_expand(entity == CTLS_ENTITY_CLIENT
                                ? &crypto->client_handshake_iv_key
                                : &crypto->server_handshake_iv_key,
                            entity == CTLS_ENTITY_CLIENT
                                ? &crypto->client_handshake_traffic_secret
                                : &crypto->server_handshake_traffic_secret,
                            CTLS_KEY_USAGE_AEAD_ENCRYPT_OR_DECRYPT,
                            info,
                            info_offset);
cleanup:
    return CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED;
}

ctls_status_t ctls_hkdf_extract(psa_key_id_t *output_key_id,
                                psa_key_id_t const *salt,
                                psa_key_id_t const *ikm_key_id) {
    ctls_crypto_t *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL_KEY_ID(salt);
    CTLS_CHECK_NULL_KEY_ID(ikm_key_id);

    ctls_status_t result = ctls_key_schedule_operator_reset(crypto);
    if (result != CTLS_STATUS_SUCCESS) return result;

    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t output_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    *output_key_id = PSA_KEY_ID_NULL;

    result = ctls_key_attributes_set(CTLS_KEY_USAGE_HKDF_EXPAND, &output_key_attributes);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    status = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXTRACT(crypto->hash_algorithm));
    if (status != PSA_SUCCESS) goto cleanup;

    status = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SALT,
                                          *salt);
    if (status != PSA_SUCCESS) goto cleanup;

    status = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          *ikm_key_id);
    if (status != PSA_SUCCESS) goto cleanup;

    status = psa_key_derivation_output_key(&output_key_attributes,
                                           &crypto->key_schedule_operator,
                                           output_key_id);
    if (status != PSA_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;
cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    if (*output_key_id != PSA_KEY_ID_NULL) { psa_destroy_key(*output_key_id); }
    psa_reset_key_attributes(&output_key_attributes);
    return CTLS_STATUS_CRYPTO_HKDF_EXTRACT_FAILED;
}

ctls_status_t ctls_hkdf_expand(psa_key_id_t *output_key_id,
                               psa_key_id_t const *prk_key_id,
                               ctls_key_usage_t const key_usage,
                               uint8_t const *info,
                               ctls_size_t const info_length) {
    ctls_crypto_t *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_KEY_ID(output_key_id);
    CTLS_CHECK_NULL_KEY_ID(prk_key_id);
    CTLS_CHECK_NULL_BUFFER(info);
    CTLS_CHECK_NULL_STRUCT(crypto);

    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t output_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    *output_key_id = PSA_KEY_ID_NULL;

    ctls_status_t result = ctls_key_attributes_set(key_usage, &output_key_attributes);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    result = ctls_key_schedule_operator_reset(crypto);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    status = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    if (status != PSA_SUCCESS) goto cleanup;

    status = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          *prk_key_id);
    if (status != PSA_SUCCESS) goto cleanup;

    status = psa_key_derivation_input_bytes(&crypto->key_schedule_operator,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            info,
                                            info_length);
    if (status != PSA_SUCCESS) goto cleanup;

    status = psa_key_derivation_output_key(&output_key_attributes,
                                           &crypto->key_schedule_operator,
                                           output_key_id);
    if (status != PSA_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;
cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    if (*output_key_id != PSA_KEY_ID_NULL) { psa_destroy_key(*output_key_id); }
    psa_reset_key_attributes(&output_key_attributes);
    return CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED;
}

/*
 * Per-record nonce (RFC 8446 §5.3): copy the 12-byte static IV, XOR the
 * sequence number into its last 8 bytes (left-padded big-endian). Same
 * sequence number must never repeat under one key — that is what the
 * record counters guarantee.
 */
ctls_status_t ctls_nonce_generate(uint8_t *buffer,
                                  uint16_t const *sequence_number,
                                  psa_key_id_t const *iv_key_id) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_KEY_ID(iv_key_id);
    CTLS_CHECK_NULL(sequence_number);

    uint8_t iv_key[CTLS_SIZE_AEAD_KEY];

    size_t iv_key_offset = 0;
    ctls_status_t const result = psa_export_key(*iv_key_id,
                                                iv_key,
                                                CTLS_SIZE_AEAD_KEY,
                                                &iv_key_offset);
    if (result != CTLS_STATUS_SUCCESS) return CTLS_STATUS_CRYPTO_KEY_EXPORT_FAILED;

    ctls_write_bytes(buffer, 0, CTLS_SIZE_NONCE, iv_key);
    for (int i = 0; i < 8; i++) {
        buffer[11 - i] ^= (uint8_t) (*sequence_number >> (i * 8U));
    }

    return CTLS_STATUS_SUCCESS;
}

/*
 * AEAD open (RFC 8446 §5.2): AES-128-GCM with the per-record nonce and the
 * unified header bytes as AAD. Tag mismatch -> AEAD_DECRYPT_FAILED; a good
 * tag simultaneously authenticates the header. Key/IV selected by
 * compile-time role.
 */
ctls_status_t ctls_decrypt(psa_key_id_t const *write_key_id,
                           psa_key_id_t const *iv_key_id,
                           uint16_t const *sequence_number,
                           uint8_t const *aad,
                           size_t const aad_len,
                           uint8_t const *ciphertext,
                           size_t const ciphertext_len,
                           uint8_t *buffer,
                           size_t *bytes_written) {
    CTLS_CHECK_NULL(sequence_number);
    CTLS_CHECK_NULL_BUFFER(aad);
    CTLS_CHECK_NULL_BUFFER(ciphertext);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(bytes_written);
    CTLS_CHECK_NULL_KEY_ID(write_key_id);
    CTLS_CHECK_NULL_KEY_ID(iv_key_id);

    psa_status_t psa_st = PSA_SUCCESS;
    uint8_t nonce[CTLS_SIZE_NONCE];

    ctls_status_t const result = ctls_nonce_generate(nonce, sequence_number, iv_key_id);
    if (result != CTLS_STATUS_SUCCESS) return result;

    psa_st = psa_aead_decrypt(*write_key_id,
                              CTLS_GCM_ALGORITHM,
                              nonce,
                              CTLS_SIZE_NONCE,
                              aad,
                              aad_len,
                              ciphertext,
                              ciphertext_len,
                              buffer,
                              ciphertext_len - 16U,
                              bytes_written);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;
cleanup:
    return CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED;
}

/*
 * AEAD seal — inverse of ctls_decrypt. Output written to ciphertext_buffer
 * is ciphertext | tag(16); bytes_written = plaintext_length + 16. Own
 * role's handshake key + IV (compile-time CTLS_CLIENT / CTLS_SERVER).
 */
ctls_status_t ctls_encrypt(psa_key_id_t const *write_key_id,
                           psa_key_id_t const *iv_key_id,
                           uint16_t const *sequence_number,
                           uint8_t const *aad,
                           ctls_size_t const aad_len,
                           uint8_t const *plaintext,
                           ctls_size_t const plaintext_length,
                           uint8_t *ciphertext_buffer,
                           size_t *bytes_written) {
    CTLS_CHECK_NULL(sequence_number);
    CTLS_CHECK_NULL_BUFFER(aad);
    CTLS_CHECK_NULL_BUFFER(plaintext);
    CTLS_CHECK_NULL_BUFFER(ciphertext_buffer);
    CTLS_CHECK_NULL(bytes_written);
    CTLS_CHECK_NULL_KEY_ID(write_key_id);
    CTLS_CHECK_NULL_KEY_ID(iv_key_id);

    psa_status_t psa_st = PSA_SUCCESS;

    uint8_t nonce[CTLS_SIZE_NONCE];
    ctls_status_t const result = ctls_nonce_generate(nonce, sequence_number, iv_key_id);
    if (result != CTLS_STATUS_SUCCESS) return result;


    psa_st = psa_aead_encrypt(*write_key_id,
                              CTLS_GCM_ALGORITHM,
                              nonce,
                              CTLS_SIZE_NONCE,
                              aad,
                              aad_len,
                              plaintext,
                              plaintext_length,
                              ciphertext_buffer,
                              plaintext_length + CTLS_SIZE_AEAD_KEY,
                              bytes_written);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;
cleanup:
    return CTLS_STATUS_CRYPTO_AEAD_ENCRYPT_FAILED;
}

ctls_status_t ctls_certificate_bytes_offset_find(uint8_t const *certificate_der,
                                                 size_t const certificate_der_length,
                                                 ctls_size_t *offset) {
    for (size_t i = 0; i + SPKI_PATTERN_LENGTH + CTLS_SIZE_ED25519_KEY_LENGTH <=
                       certificate_der_length; i++) {
        if (memcmp(&certificate_der[i], SPKI_PATTERN, SPKI_PATTERN_LENGTH) == 0) {
            *offset = i + SPKI_PATTERN_LENGTH;
            break;
        }
    }
    if (*offset == certificate_der_length) return CTLS_STATUS_CRYPTO_KEY_IMPORT_FAILED;

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_certificate_key_pair_import(uint8_t const *private_certificate_der,
                                               size_t const
                                               private_certificate_der_length,
                                               psa_key_id_t *key_pair_id) {
    ctls_crypto_t const *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL_BUFFER(private_certificate_der);
    CTLS_CHECK_NULL_KEY_ID(key_pair_id);

    /* Ed25519 SubjectPublicKeyInfo in DER:
     * 30 05 06 03 2b 65 70  -- AlgorithmIdentifier (OID 1.3.101.112)
     * 03 21 00              -- BIT STRING, 33 bytes, 0 unused bits
     * <32 bytes>            -- raw Ed25519 public key */


    ctls_size_t key_offset = 0;
    ctls_status_t result = ctls_certificate_bytes_offset_find(private_certificate_der,
        private_certificate_der_length,
        &key_offset);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    *key_pair_id = PSA_KEY_ID_NULL;
    psa_key_attributes_t certificate_private_key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    result = ctls_key_attributes_set(CTLS_KEY_USAGE_SIGN_MESSAGE,
                                     &certificate_private_key_attributes);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    psa_status_t const psa_st = psa_import_key(&certificate_private_key_attributes,
                                               &private_certificate_der[key_offset],
                                               CTLS_SIZE_ED25519_KEY_LENGTH,
                                               key_pair_id);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;
cleanup:
    psa_reset_key_attributes(&certificate_private_key_attributes);
    return CTLS_STATUS_CRYPTO_KEY_IMPORT_FAILED;
}

ctls_status_t ctls_certificate_public_key_import(uint8_t const *public_certificate_der,
                                                 size_t const
                                                 public_certificate_der_length,
                                                 psa_key_id_t *key_id) {
    ctls_crypto_t const *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL_BUFFER(public_certificate_der);
    CTLS_CHECK_NULL(key_id);

    /* Ed25519 SubjectPublicKeyInfo in DER:
     * 30 05 06 03 2b 65 70  -- AlgorithmIdentifier (OID 1.3.101.112)
     * 03 21 00              -- BIT STRING, 33 bytes, 0 unused bits
     * <32 bytes>            -- raw Ed25519 public key */

    ctls_size_t key_offset = public_certificate_der_length;
    ctls_status_t result = ctls_certificate_bytes_offset_find(public_certificate_der,
        public_certificate_der_length,
        &key_offset);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    *key_id = PSA_KEY_ID_NULL;
    psa_key_attributes_t certificate_public_key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    result = ctls_key_attributes_set(CTLS_KEY_USAGE_VERIFY_SIGNATURE,
                                     &certificate_public_key_attributes);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    psa_status_t const psa_st = psa_import_key(&certificate_public_key_attributes,
                                               &public_certificate_der[key_offset],
                                               CTLS_SIZE_ED25519_KEY_LENGTH,
                                               key_id);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;

cleanup:
    psa_reset_key_attributes(&certificate_public_key_attributes);
    return CTLS_STATUS_CRYPTO_KEY_IMPORT_FAILED;
}

/*
 * CertificateVerify signature (RFC 8446 §4.4.3): Ed25519 over
 * 64 x 0x20 | context string | 0x00 | Transcript-Hash. Private key comes
 * from this entity's PKCS#8 DER in the certs header; signature lands in
 * hshk_data's signed-bytes slot for the hsmg layer to reference.
 */
ctls_status_t ctls_signed_bytes_generate(ctls_entity_t const entity) {
    ctls_crypto_t *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL_STRUCT(hshk_data);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER) return
            CTLS_STATUS_CRYPTO_INVALID_ARG;

    psa_status_t psa_st = PSA_SUCCESS;

    uint8_t *signature = entity == CTLS_ENTITY_CLIENT
                             ? hshk_data->client_signature
                             : hshk_data->server_signature;

    /* context strings [RFC 8446 §4.4.3] */
    uint8_t info[64U + 34U + 1U + 32U]; /* max context string is 34 bytes */
    ctls_size_t info_offset = 0U;
    ctls_status_t const result = ctls_context_string_build(info,
                                                           &info_offset,
                                                           entity,
                                                           CTLS_KEY_TYPE_SIGNED_BYTES);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    size_t signed_bytes_written = 0U;
    psa_st = psa_sign_message(crypto->self_certificate_key_pair,
                              CTLS_CERTIFICATE_SIGNATURE_ALGORITHM,
                              info,
                              info_offset,
                              signature,
                              CTLS_SIZE_SIGNED_BYTES,
                              &signed_bytes_written);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;

cleanup:
    return CTLS_STATUS_CRYPTO_SIGNATURE_FAILED;
}


/*
 * Verify the peer's CertificateVerify: rebuild the same §4.4.3 content
 * from the local transcript, import the peer's Ed25519 public key from its
 * certificate (SPKI scan), psa_verify_message against the received
 * signature stored in hshk_data.
 */
ctls_status_t ctls_signed_bytes_verify(psa_key_id_t const *public_key_id,
                                       ctls_entity_t const entity) {
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();
    ctls_crypto_t const *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_STRUCT(hshk_data);
    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL_KEY_ID(public_key_id);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER) return
            CTLS_STATUS_CRYPTO_INVALID_ARG;

    psa_status_t psa_st = PSA_SUCCESS;

    uint8_t info[64U + 34U + 1U + 32U]; /* max context string is 34 bytes */
    ctls_size_t info_offset = 0U;
    ctls_status_t const result = ctls_context_string_build(info,
                                                           &info_offset,
                                                           entity,
                                                           CTLS_KEY_TYPE_SIGNED_BYTES);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    psa_st = psa_verify_message(*public_key_id,
                                CTLS_CERTIFICATE_SIGNATURE_ALGORITHM,
                                info,
                                info_offset,
                                entity == CTLS_ENTITY_CLIENT
                                    ? hshk_data->client_signature
                                    : hshk_data->server_signature,
                                CTLS_SIZE_SIGNED_BYTES);
    if (psa_st != PSA_SUCCESS) goto cleanup;
    return CTLS_STATUS_SUCCESS;

cleanup:
    return CTLS_STATUS_CRYPTO_SIGNATURE_VERIFY_FAILED;
}

/*
 * finished_key = HKDF-Expand-Label(base key, "finished", "", 32)
 * — RFC 8446 §4.4.4; per entity, stored in hshk_data.
 */
ctls_status_t ctls_finished_key_generate(ctls_entity_t const entity) {
    ctls_crypto_t *crypto = ctls_crypto_get();

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER) return
            CTLS_STATUS_CRYPTO_INVALID_ARG;
    CTLS_CHECK_NULL_STRUCT(crypto);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t info[32U];
    ctls_size_t info_offset = 0U;

    result = ctls_context_string_build(info,
                                       &info_offset,
                                       entity,
                                       CTLS_KEY_TYPE_FINISHED_KEY);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;


    result = ctls_hkdf_expand(entity == CTLS_ENTITY_CLIENT
                                  ? &crypto->client_finished_key
                                  : &crypto->server_finished_key,
                              entity == CTLS_ENTITY_CLIENT
                                  ? &crypto->client_handshake_traffic_secret
                                  : &crypto->server_handshake_traffic_secret,
                              CTLS_KEY_USAGE_HMAC,
                              info,
                              info_offset);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;
    return CTLS_STATUS_SUCCESS;

cleanup:
    return CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED;
}


ctls_status_t ctls_verify_data_generate(ctls_entity_t const entity) {
    /* verify_data = HMAC-SHA256(finished_key, transcript_hash)
     * [RFC 8446 §4.4.4] */
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    ctls_crypto_t const *crypto = ctls_crypto_get();

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER) return
            CTLS_STATUS_CRYPTO_INVALID_ARG;

    psa_status_t psa_st = PSA_SUCCESS;


    size_t bytes_written;

    psa_st = psa_mac_compute(entity == CTLS_ENTITY_CLIENT
                                 ? crypto->client_finished_key
                                 : crypto->server_finished_key,
                             PSA_ALG_HMAC(crypto->hash_algorithm),
                             hshk_data->transcript_hash,
                             CTLS_SIZE_HASH,
                             entity == CTLS_ENTITY_CLIENT
                                 ? hshk_data->client_verify_data
                                 : hshk_data->server_verify_data,
                             CTLS_SIZE_HASH,
                             &bytes_written);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    if (entity == CTLS_ENTITY_CLIENT) {
        hshk_data->client_verify_data_length = bytes_written;
    } else {
        hshk_data->server_verify_data_length = bytes_written;
    }

    return CTLS_STATUS_SUCCESS;

cleanup:
    return CTLS_STATUS_CRYPTO_HMAC_VERIFY_DATA_FAILED;
}

ctls_status_t ctls_application_key_schedule(ctls_entity_t const entity) {
    ctls_crypto_t *crypto = ctls_crypto_get();
    CTLS_CHECK_NULL_STRUCT(crypto);

    ctls_status_t result = ctls_master_secret_generate(crypto);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_application_traffic_secret_generate(crypto, entity);
    if (result != CTLS_STATUS_SUCCESS) return result;


    /* Keys switched to handshake traffic keys — new epoch. RFC 9147 §6.1
       numbering: epoch 0 plaintext, 1 early data (unsupported, skipped),
       2 handshake keys. */
    result = ctls_epoch_counter_increment();
    if (result != CTLS_STATUS_SUCCESS) return result;
    return ctls_epoch_counter_increment();
}

ctls_status_t ctls_master_secret_generate(ctls_crypto_t *crypto) {
    CTLS_CHECK_NULL_STRUCT(crypto);

    static const uint8_t ZEROS[32] = {0};
    psa_status_t psa_st = PSA_SUCCESS;

    psa_key_attributes_t ikm_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t ikm = PSA_KEY_ID_NULL;

    ctls_status_t result = ctls_key_schedule_operator_reset(crypto);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    result = ctls_key_attributes_set(CTLS_KEY_USAGE_HKDF_EXTRACT, &ikm_attributes);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    psa_st = psa_import_key(&ikm_attributes, ZEROS, CTLS_SIZE_HASH, &ikm);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    result = ctls_hkdf_extract(&crypto->master_secret, &crypto->derived_secret, &ikm);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    return CTLS_STATUS_SUCCESS;
cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    if (ikm != PSA_KEY_ID_NULL) { psa_destroy_key(ikm); }
    psa_reset_key_attributes(&ikm_attributes);

    return CTLS_STATUS_CRYPTO_HKDF_EXTRACT_FAILED;
}

ctls_status_t ctls_application_traffic_secret_generate(
    ctls_crypto_t *crypto,
    ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(crypto);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER) return
            CTLS_STATUS_EXTN_INVALID_ENTITY;

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t info[80U];
    ctls_size_t info_offset = 0U;

    result = ctls_context_string_build(info,
                                       &info_offset,
                                       entity,
                                       CTLS_KEY_TYPE_APPLICATION_TRAFFIC_SECRET);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    return ctls_hkdf_expand(entity == CTLS_ENTITY_CLIENT
                                ? &crypto->client_application_traffic_secret
                                : &crypto->server_application_traffic_secret,
                            &crypto->master_secret,
                            CTLS_KEY_USAGE_HKDF_EXPAND,
                            info,
                            info_offset);

cleanup:
    return CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED;
}

ctls_status_t ctls_exporter_master_secret_generate(ctls_crypto_t *crypto) {
    CTLS_CHECK_NULL_STRUCT(crypto);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t info[80U];
    ctls_size_t info_offset = 0U;

    result = ctls_context_string_build(info,
                                       &info_offset,
                                       CTLS_ENTITY_CLIENT,
                                       CTLS_KEY_TYPE_EXPORTER_MASTER_SECRET);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    return ctls_hkdf_expand(&crypto->exporter_master_secret,
                            &crypto->master_secret,
                            CTLS_KEY_USAGE_HKDF_EXPAND,
                            info,
                            info_offset);

cleanup:
    return CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED;
}

ctls_status_t ctls_application_write_key_generate(ctls_crypto_t *crypto,
                                                  ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(crypto);
    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER) return
            CTLS_STATUS_EXTN_INVALID_ENTITY;

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t info[32U];
    ctls_size_t info_offset = 0U;

    result = ctls_context_string_build(info,
                                       &info_offset,
                                       entity,
                                       CTLS_KEY_TYPE_APPLICATION_TRAFFIC_WRITE_KEYS);
    if (result != CTLS_STATUS_SUCCESS) goto cleanup;

    return ctls_hkdf_expand(entity == CTLS_ENTITY_CLIENT
                                ? &crypto->client_application_write_key
                                : &crypto->server_application_write_key,
                            entity == CTLS_ENTITY_CLIENT
                                ? &crypto->client_application_traffic_secret
                                : &crypto->server_application_traffic_secret,
                            CTLS_KEY_USAGE_AEAD_ENCRYPT_OR_DECRYPT,
                            info,
                            info_offset);
cleanup:
    return CTLS_STATUS_CRYPTO_HKDF_EXPAND_FAILED;
}

