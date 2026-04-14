//
// Created by Sanjay Kumar Kumaravelan on 10/04/26.
//

#include "ctls/types.h"
#include "ctls/internal.h"
#include "ctls/bytes.h"

ctls_op_status_t tls_build_record_client_hello(
    tls_record_body_t *tls_record_body, ctls_record_t *record,
    ctls_profile_t const *profile) {
    tls_record_body->message_type = CTLS_HANDSHAKE_TYPE_CLIENT_HELLO;
    tls_record_body->client_hello.legacy_version = CTLS_VERSION_1_2;
    tls_record_body->client_hello.legacy_session_id = 0x00;
    tls_record_body->client_hello.cipher_suit_length = 0x0002;
    tls_record_body->client_hello.cipher_suite[0] = profile->
            cipher_suite;
    tls_record_body->client_hello.legacy_compression_methods_length =
            0x01;
    tls_record_body->client_hello.legacy_compression_methods[0] = 0x00;


    memcpy(tls_record_body->client_hello.random,
           record->body.client_hello.random,
           CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM);

    tls_record_body->client_hello.extensions.extension_supported_version
            .extension_type =
            CTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS;
    tls_record_body->client_hello.extensions.extension_supported_version
            .extension_data_length = 0x0003;
    tls_record_body->client_hello.extensions.extension_supported_version
            .extension_data.data[0] = profile->version;
    tls_record_body->client_hello.extensions.extension_supported_version
            .extension_data.data_length = 0x02;

    tls_record_body->client_hello.extensions.extension_supported_groups
            .extension_type = CTLS_EXTENSION_TYPE_SUPPORTED_GROUPS;
    tls_record_body->client_hello.extensions.extension_supported_groups
            .extension_data_length = 0x0004;
    tls_record_body->client_hello.extensions.extension_supported_groups
            .extension_data.data[0] = profile->dhe_group;
    tls_record_body->client_hello.extensions.extension_supported_groups
            .extension_data.data_length = 0x0002;

    tls_record_body->client_hello.extensions.
            extension_signature_algorithms
            .extension_type =
            CTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS;
    tls_record_body->client_hello.extensions.
            extension_signature_algorithms
            .extension_data_length = 0x0004;
    tls_record_body->client_hello.extensions.
            extension_signature_algorithms
            .extension_data.data[0] = profile->signature_algorithm;
    tls_record_body->client_hello.extensions.extension_supported_groups
            .extension_data.data_length = 0x0002;


    tls_record_body->client_hello.extensions.
            extension_key_share
            .extension_type = CTLS_EXTENSION_TYPE_KEY_SHARE;
    tls_record_body->client_hello.extensions.
            extension_key_share
            .extension_data_length = 0x0026; // 38 bytes
    tls_record_body->client_hello.extensions.
            extension_key_share
            .extension_data.key_length =
            CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE;
    tls_record_body->client_hello.extensions.extension_key_share.
            extension_data.key_share_group = profile->dhe_group;

    memcpy(
        tls_record_body->client_hello.extensions.extension_key_share.
        extension_data.key, record->body.client_hello.random,
        CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM);

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS
    };
}

ctls_op_status_t tls_serialize_client_hello(
    tls_record_body_t const *record_body,
    uint8_t *buffer, size_t *offset) {
    CTLS_CHECK_NULL(record_body);
    CTLS_CHECK_NULL(buffer);


    /* ---- handshake header (4 bytes) ---- */
    ctls_write_u8(buffer, offset, record_body->message_type); // 0x01

    /* uint24 body length — fill after body is written          */
    size_t body_length_offset = *offset;
    ctls_write_u8(buffer, offset, 0x00);
    ctls_write_u8(buffer, offset, 0x00);
    ctls_write_u8(buffer, offset, 0x00);

    size_t body_start = *offset;

    /* ---- ClientHello body ---- */

    /* legacy_version = 0x0303 */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.legacy_version);

    /* random (32 bytes) — from your cTLS record */
    memcpy(buffer + *offset, record_body->client_hello.random,
           CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM);
    offset += CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM;

    /* legacy_session_id length = 0x00 (empty) */
    ctls_write_u8(buffer, offset,
                  record_body->client_hello.legacy_session_id);

    /* cipher_suites length = 0x0002, then one suite */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.cipher_suit_length);
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.cipher_suite[0]);

    /* legacy_compression_methods length = 0x01, then 0x00 */
    ctls_write_u8(buffer, offset,
                  record_body->client_hello.
                  legacy_compression_methods_length);
    ctls_write_u8(buffer, offset,
                  record_body->client_hello.legacy_compression_methods[0]);

    /* ---- extensions ---- */
    /* extensions length placeholder — fill after extensions */
    size_t extension_length_offset = *offset;
    ctls_write_u16(buffer, offset, 0x0000);

    size_t const extension_start = *offset;

    /* supported_versions: type(2) + ext_len(2) + list_len(1) + version(2) = 7 */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_supported_version.extension_type);
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_supported_version.extension_data_length);
    /* ext data length = 3 */
    ctls_write_u8(buffer, offset,
                  record_body->client_hello.extensions.
                  extension_supported_version.extension_data.data_length);
    /* versions list length = 2 (1 byte per §4.2.1) */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_supported_version.extension_data.data[0]);

    /* supported_groups: type(2) + ext_len(2) + list_len(2) + group(2) = 8 */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_supported_groups.extension_type);
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_supported_groups.extension_data_length);
    /* ext data length = 4 */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_supported_groups.extension_data.data_length);
    /* named_group_list length = 2 */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_supported_groups.extension_data.data[0]);

    /* signature_algorithms: type(2) + ext_len(2) + list_len(2) + alg(2) = 8 */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_signature_algorithms.extension_type);
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_signature_algorithms.extension_data_length);
    /* ext data length = 4 */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_signature_algorithms.extension_data.data_length);
    /* supported_signature_algorithms length = 2 */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.
                   extension_signature_algorithms.extension_data.data[0]);

    /* key_share: type(2) + ext_len(2) + client_shares_len(2)
     *            + group(2) + key_ex_len(2) + key(32) = 42    */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.extension_key_share.
                   extension_type);
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.extension_key_share.
                   extension_data_length); /* ext data length = 38 */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.extension_key_share.
                   extension_data.key_length); /* client_shares length = 36 */
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.extension_key_share.
                   extension_data.key_share_group);
    ctls_write_u16(buffer, offset,
                   record_body->client_hello.extensions.extension_key_share.
                   extension_data.key_length); /* key_exchange length = 32 */
    memcpy(buffer + *offset,
           record_body->client_hello.extensions.extension_key_share.
           extension_data.key,
           CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE);
    offset += CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE;

    /* backfill extensions length */
    size_t const extension_length = *offset - extension_start;
    ctls_write_to_offset_u16(buffer, &extension_length_offset,
                             extension_length);

    /* backfill uint24 body length */
    size_t const body_len = *offset - body_start;
    ctls_write_u24(buffer, &body_length_offset, body_len);

    return (ctls_op_status_t){
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
        .source = CTLS_ERROR_SOURCE_INTERNAL
    };
}
