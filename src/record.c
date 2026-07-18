// Created by Sanjay Kumar Kumaravelan on 15/04/26.
//

/*
 * cTLS record layer. See record.h for the design overview (record forms,
 * unified header layout, counter semantics). Comments here give exact byte
 * layouts per function.
 *
 * Encrypted record on the wire:
 *
 *     unified header (clear, = AEAD AAD) | AES-128-GCM(body) | tag(16)
 */

#include <string.h>
#include "ctls/ctls.h"
#include "ctls/bytes.h"
#include "ctls/record.h"
#include "ctls/templates.h"

/*
 * Serialized header size = AAD size, from the config bits:
 * octet(1) + sequence(s_bit ? 2 : 1) + length(l_bit ? 2 : 0) — 2..5 bytes.
 * Stored in unified_header->aad_length. CID unsupported.
 */
ctls_status_t ctls_aad_length_calculate(ctls_unified_header_t *unified_header) {
    CTLS_CHECK_NULL_STRUCT(unified_header);

    if (unified_header->config_octet.c_bit != 0) return CTLS_STATUS_RECD_AAD_LEN_CID;

#if CTLS_STREAM
    /* Reliable transport: sequence number omitted from the wire (draft §2.2). */
    unified_header->aad_length = 1U + (unified_header->config_octet.l_bit ? 2U : 0U);
#else
    unified_header->aad_length = 1U + (unified_header->config_octet.s_bit ? 2U : 1U) + (
                                     unified_header->config_octet.l_bit ? 2U : 0U);
#endif

    return CTLS_STATUS_SUCCESS;
}

/*
 * Record counters, single sequence space for the connection: every record —
 * created or received — consumes one sequence number, so both peers stay in
 * lockstep (CH=0, SH=1, server flight=2, ...). Increment happens at the end
 * of ctls_record_serialize / ctls_record_deserialize; headers stamp the
 * counter's current value via ctls_unified_header_build before that.
 *
 * Epoch counts key changes (DTLS 1.3 style), not messages: bump it where
 * the key schedule switches keys. On receive the epoch is reconstructed
 * from the header's 2 bits and synced back in ctls_record_decrypt.
 */
ctls_status_t ctls_sequence_number_counter_increment(void) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    CTLS_CHECK_NULL(hshk_data);

    hshk_data->sequence_number++;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_sequence_number_counter_get(uint16_t *sequence_number) {
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();
    CTLS_CHECK_NULL(hshk_data);
    CTLS_CHECK_NULL(sequence_number);

    *sequence_number = hshk_data->sequence_number;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_sequence_number_counter_reset(void) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    CTLS_CHECK_NULL(hshk_data);

    hshk_data->sequence_number = 0;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_epoch_counter_increment(void) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    CTLS_CHECK_NULL(hshk_data);

    hshk_data->epoch++;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_epoch_counter_get(uint64_t *epoch) {
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();
    CTLS_CHECK_NULL(hshk_data);
    CTLS_CHECK_NULL(epoch);

    *epoch = hshk_data->epoch;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_epoch_counter_reset(void) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    CTLS_CHECK_NULL(hshk_data);

    hshk_data->epoch = 0;
    return CTLS_STATUS_SUCCESS;
}

/*
 * Snapshot current hshk_data counters into a header at record creation:
 * sequence number (s_bit picks 1- vs 2-byte encoding), full epoch plus its
 * compressed 2 bits, l_bit from length. length is usually 0 here — for
 * encrypted records the final value is known only after body serialization.
 */
ctls_status_t ctls_unified_header_build(ctls_unified_header_t *unified_header,
                                        uint16_t const length) {
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(unified_header);
    CTLS_CHECK_NULL_STRUCT(hshk_data);

    unified_header->config_octet.c_bit = 0;
#if CTLS_STREAM
    /* Reliable transport: S bit MUST be cleared (draft §2.2). */
    unified_header->config_octet.s_bit = 0;
#else
    unified_header->config_octet.s_bit = (hshk_data->sequence_number > 0xFFu) ? 1u : 0u;
#endif
    unified_header->config_octet.l_bit = (length > 0u) ? 1u : 0u;
    unified_header->config_octet.epoch = ctls_epoch_compress(&hshk_data->epoch);

    unified_header->sequence_number = hshk_data->sequence_number;
    unified_header->length = length;
    unified_header->epoch = hshk_data->epoch;

    return ctls_aad_length_calculate(unified_header);
}

/*
 * Header struct -> wire bytes (RFC 9147 §4 model):
 *
 *     config octet(1): fixed prefix | C | S | L | EE(2 epoch bits)
 *     | sequence number (u8 if S=0, u16 if S=1)
 *     | length (u16, only if L=1)
 *
 * These bytes double as the AEAD AAD for encrypted records.
 */
ctls_status_t ctls_unified_header_serialize(ctls_unified_header_t const *unified_header,
                                            uint8_t *buffer,
                                            ctls_size_t *offset) {
    CTLS_CHECK_NULL_STRUCT(unified_header);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (unified_header->config_octet.c_bit != 0) return
            CTLS_STATUS_RECD_HDR_SERIALIZE_CID;

    if (unified_header->config_octet.s_bit != 0 && unified_header->config_octet.s_bit !=
        1) return CTLS_STATUS_RECD_HDR_SERIALIZE_SEQ;

    uint8_t octet = CTLS_RECD_CONFIG_OCTET_FIXED_VALUE;
    if (unified_header->config_octet.c_bit) octet |= CTLS_RECD_CONFIG_OCTET_C_MASK;
    if (unified_header->config_octet.s_bit) octet |= CTLS_RECD_CONFIG_OCTET_S_MASK;
    if (unified_header->config_octet.l_bit) octet |= CTLS_RECD_CONFIG_OCTET_L_MASK;
    octet |= ctls_epoch_compress(&unified_header->epoch) &
            CTLS_RECD_CONFIG_OCTET_EPOCH_MASK;

    buffer[(*offset)++] = octet;

    ctls_status_t result = CTLS_STATUS_SUCCESS;
#if CTLS_STREAM
    /* Reliable transport: sequence number omitted from the wire (draft §2.2). */
#else
    if (unified_header->config_octet.s_bit == 0) {
        result = ctls_write_u8(buffer, offset, (uint8_t) unified_header->sequence_number,
                               CTLS_SIZE_WIRE_BUFFER);
    } else {
        result = ctls_write_u16(buffer, offset, unified_header->sequence_number,
                                CTLS_SIZE_WIRE_BUFFER);
    }
    if (result != CTLS_STATUS_SUCCESS) return result;
#endif

    if (unified_header->config_octet.l_bit == 1) {
        result = ctls_write_u16(buffer, offset, unified_header->length, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    return CTLS_STATUS_SUCCESS;
}


/*
 * Wire bytes -> header struct, inverse of serialize. The 2 epoch wire bits
 * are expanded against the epoch value already in the struct — the caller
 * (ctls_record_decrypt) seeds it with the current epoch from hshk_data.
 * Also recomputes aad_length from the parsed config bits.
 */
ctls_status_t ctls_unified_header_deserialize(ctls_unified_header_t *unified_header,
                                              uint8_t const *buffer,
                                              ctls_size_t *offset) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(unified_header);
    CTLS_CHECK_BOUNDS(*offset, 2, CTLS_SIZE_WIRE_BUFFER);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint8_t const first_part = buffer[(*offset)++];

    unified_header->config_octet.c_bit =
            (first_part & CTLS_RECD_CONFIG_OCTET_C_MASK) != 0;
    unified_header->config_octet.s_bit =
            (first_part & CTLS_RECD_CONFIG_OCTET_S_MASK) != 0;
    unified_header->config_octet.l_bit =
            (first_part & CTLS_RECD_CONFIG_OCTET_L_MASK) != 0;
    unified_header->config_octet.epoch = first_part & CTLS_RECD_CONFIG_OCTET_EPOCH_MASK;

    if (unified_header->config_octet.c_bit == 1) return
            CTLS_STATUS_RECD_HDR_DESERIALIZE_CID;

    if (unified_header->config_octet.s_bit > 1 || unified_header->config_octet.s_bit < 0)
        return CTLS_STATUS_RECD_HDR_DESERIALIZE_SEQ;

#if CTLS_STREAM
    /*
     * Reliable transport: sequence number isn't on the wire (draft §2.2) —
     * the transport itself guarantees order, so trust the local counter
     * instead of reading one. Still needed below (replay check) and for
     * AEAD nonce derivation.
     */
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();
    CTLS_CHECK_NULL_STRUCT(hshk_data);
    unified_header->sequence_number = hshk_data->sequence_number;
#else
    if (unified_header->config_octet.s_bit == 0) {
        uint8_t sequence_number_u8 = 0;
        result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &sequence_number_u8);
        if (result != CTLS_STATUS_SUCCESS) return result;
        unified_header->sequence_number = sequence_number_u8;
    } else {
        result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER,
                               &unified_header->sequence_number);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }
#endif
    if (unified_header->config_octet.l_bit == 1) {
        result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &unified_header->length);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_epoch_expand(unified_header->config_octet.epoch, &unified_header->epoch);

    return ctls_aad_length_calculate(unified_header);
}

ctls_status_t ctls_unified_header_length_update(ctls_unified_header_t *unified_header,
                                                uint16_t const length) {
    CTLS_CHECK_NULL_STRUCT(unified_header);

    unified_header->length = length;
    unified_header->config_octet.l_bit = (length > 0u) ? 1u : 0u;
    return ctls_aad_length_calculate(unified_header);
}

ctls_status_t ctls_record_preprocess(uint8_t const *buffer,
                                     ctls_size_t const bytes_received,
                                     ctls_record_t *record,
                                     uint8_t *plaintext,
                                     ctls_size_t *plaintext_offset) {
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_STRUCT(hshk_data);


    uint8_t content_type_byte = buffer[0];
    ctls_status_t result = CTLS_STATUS_SUCCESS;
    ctls_size_t offset = 0U;

    // Checking for Unified Header first (First 3 bits == 001)
    // 0xE0 is the bitmask 0b11100000. 0x20 is 0b00100000.
    if ((content_type_byte & 0xE0) == 0x20) {
        record->type = CTLS_RECORD_TYPE_ENCRYPTED;

        result = ctls_unified_header_deserialize(&record->unified_header,
                                                 buffer,
                                                 &offset);
        if (result != CTLS_STATUS_SUCCESS) return result;

        if (record->unified_header.aad_length == 0) return
                CTLS_STATUS_RECD_INVALID_AAD_LENGTH;

        if ((record->unified_header.epoch & 0x03) != (hshk_data->epoch & 0x03)) return
                CTLS_STATUS_RECD_EPOCH_MISMATCH;
        if (record->unified_header.sequence_number != hshk_data->sequence_number) return
                CTLS_STATUS_RECD_SEQUENCE_NUMBER_MISMATCH;

        if (record->unified_header.length == 0) {
            record->unified_header.length =
                    bytes_received - (
                        record->unified_header.aad_length + CTLS_SIZE_AEAD_TAG);
        }

        result = ctls_record_decrypt(record,
                                     buffer,
                                     plaintext,
                                     plaintext_offset,
                                     CTLS_PHASE_HANDSHAKE,
                                     CTLS_ENTITY_SERVER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        /* Inner plaintext layout is body || content_type (RFC 8446 §5.2);
         * content_type is the last byte, at index (length - 1), not at
         * plaintext_offset itself (that's the count, one past the end). */
        content_type_byte = plaintext[*plaintext_offset - 1];
    } else {
        /* Plaintext: first byte is content_type. */
        record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    }

    switch (content_type_byte) {
        case CTLS_RECD_CONTENT_TYPE_INVALID:
        case CTLS_RECD_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
        case CTLS_RECD_CONTENT_TYPE_ALERT:
        case CTLS_RECD_CONTENT_TYPE_HANDSHAKE:
        case CTLS_RECD_CONTENT_TYPE_CTLS_HANDSHAKE:
        case CTLS_RECD_CONTENT_TYPE_APPLICATION_DATA:
        case CTLS_RECD_CONTENT_TYPE_HEARTBEAT:
            record->content_type = content_type_byte;
            return CTLS_STATUS_SUCCESS;
        default:
            return CTLS_STATUS_RECD_INVALID_CONTENT_TYPE;
    }
}

/*
 * Record struct -> final wire bytes, dispatched on record type + message
 * type. PLAINTEXT (CH/SH) serializes straight into buffer. ENCRYPTED
 * flights serialize header into buffer and body into the plaintext scratch,
 * then encrypt inside their to_wire. On success consumes one sequence
 * number (see counter block above).
 */
ctls_status_t ctls_record_serialize(ctls_record_t *record,
                                    ctls_hsmg_type_t const hsmg_type,
                                    uint8_t *buffer,
                                    ctls_size_t *offset,
                                    ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    ctls_status_t result = ctls_wire_buffer_clear(buffer, offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (record->type == CTLS_RECORD_TYPE_PLAINTEXT) {
        switch (hsmg_type) {
            case CTLS_HSMG_TYPE_CLIENT_HELLO:
                result = ctls_recd_client_hello_to_wire(buffer,
                                                        offset,
                                                        record,
                                                        CTLS_WIRE_FORMAT_DEFAULT);
                break;
            case CTLS_HSMG_TYPE_SERVER_HELLO:
                result = ctls_recd_server_hello_to_wire(buffer,
                                                        offset,
                                                        record,
                                                        CTLS_WIRE_FORMAT_DEFAULT);
                break;
            case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS:
            case CTLS_HSMG_TYPE_CERTIFICATE_REQUEST:
            case CTLS_HSMG_TYPE_CERTIFICATE:
            case CTLS_HSMG_TYPE_CERTIFICATE_VERIFY:
            case CTLS_HSMG_TYPE_FINISHED:
            case CTLS_HSMG_TYPE_CLIENT_FLIGHT:
            case CTLS_HSMG_TYPE_SERVER_FLIGHT:
                return CTLS_STATUS_RECD_SER_PLAIN_ENCRYPTED_MSG;
            default:
                return CTLS_STATUS_RECD_SER_PLAIN_UNKNOWN_MSG;
        }
    }
    if (record->type == CTLS_RECORD_TYPE_ENCRYPTED) {
        switch (hsmg_type) {
            case CTLS_HSMG_TYPE_CLIENT_FLIGHT: {
                result = ctls_recd_client_flight_to_wire(buffer,
                                                         offset,
                                                         record,
                                                         CTLS_WIRE_FORMAT_DEFAULT,
                                                         entity);
            }
            break;
            case CTLS_HSMG_TYPE_SERVER_FLIGHT: {
                result = ctls_recd_server_flight_to_wire(buffer,
                                                         offset,
                                                         record,
                                                         CTLS_WIRE_FORMAT_DEFAULT,
                                                         entity);
            }
            break;
            case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS:
            case CTLS_HSMG_TYPE_CERTIFICATE_REQUEST:
            case CTLS_HSMG_TYPE_CERTIFICATE:
            case CTLS_HSMG_TYPE_CERTIFICATE_VERIFY:
            case CTLS_HSMG_TYPE_FINISHED: return CTLS_STATUS_RECD_SER_ENC_PLAINTEXT_MSG;
            default: return CTLS_STATUS_RECD_SER_ENC_UNKNOWN_MSG;
        }
    }
    if (result != CTLS_STATUS_SUCCESS) return result;

    /* record produced — consume one sequence number */
    return ctls_sequence_number_counter_increment();
}

/*
 * Received wire bytes -> record struct, dispatched on the message type the
 * handshake state machine expects (cTLS has no content-type byte on
 * encrypted records to dispatch on). Decryption happens inside the
 * per-message to_struct. On success consumes one sequence number.
 */
ctls_status_t ctls_record_deserialize(ctls_record_t *record,
                                      ctls_hsmg_type_t const hsmg_type,
                                      uint8_t const *buffer,
                                      ctls_size_t const bytes_received) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_STRUCT(record);
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    result = ctls_record_preprocess(buffer,
                                    bytes_received,
                                    record,
                                    plaintext,
                                    &plaintext_offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (record->content_type == CTLS_RECD_CONTENT_TYPE_ALERT) {
        return ctls_recd_alert_to_struct(record, buffer);
    }

    if (record->content_type != CTLS_RECD_CONTENT_TYPE_CTLS_HANDSHAKE)
        return CTLS_STATUS_RECD_INVALID_CONTENT_TYPE;

    ctls_size_t offset = 0;

    result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    switch (hsmg_type) {
        case CTLS_HSMG_TYPE_CLIENT_HELLO:
            result = ctls_recd_client_hello_to_struct(record, buffer, &offset);
            break;
        case CTLS_HSMG_TYPE_SERVER_HELLO:
            result = ctls_recd_server_hello_to_struct(record, buffer, &offset);
            break;
        case CTLS_HSMG_TYPE_SERVER_FLIGHT:
            result = ctls_recd_server_flight_to_struct(record, plaintext);
            break;
        case CTLS_HSMG_TYPE_CLIENT_FLIGHT:
            result = ctls_recd_client_flight_to_struct(record, plaintext);
            break;
        case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS:
        case CTLS_HSMG_TYPE_CERTIFICATE_REQUEST:
        case CTLS_HSMG_TYPE_CERTIFICATE:
        case CTLS_HSMG_TYPE_CERTIFICATE_VERIFY:
        case CTLS_HSMG_TYPE_FINISHED:
            result = CTLS_STATUS_RECD_DESER_STANDALONE_MSG;
            break;
        default:
            result = CTLS_STATUS_RECD_DESER_UNKNOWN_MSG;
    }
    if (result != CTLS_STATUS_SUCCESS) return result;

    /* record consumed — keep our counter in lockstep with the peer */
    return ctls_sequence_number_counter_increment();
}

ctls_status_t ctls_recd_buffer_clear(ctls_record_t *record_buffer) {
    CTLS_CHECK_NULL_STRUCT(record_buffer);

    memset(record_buffer, 0, sizeof(ctls_record_t));

    return CTLS_STATUS_SUCCESS;
}

/*
 * Body plaintext -> encrypted record bytes in buffer:
 *
 *     unified header (clear, AAD) | AES-128-GCM(plaintext) | tag(16)
 *
 * Header is serialized here so its bytes and the AAD are identical by
 * construction; the AEAD tag binds them (RFC 8446 §5.2 model). The
 * receiver's tag check is what authenticates the header.
 */
ctls_status_t ctls_record_encrypt(uint8_t *buffer,
                                  ctls_size_t *offset,
                                  ctls_unified_header_t const *unified_header,
                                  uint8_t const *plaintext,
                                  ctls_size_t const plaintext_length,
                                  ctls_size_t *ciphertext_length,
                                  ctls_phase_t const phase,
                                  ctls_entity_t const entity) {
    ctls_crypto_t const *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL_STRUCT(unified_header);

    size_t ciphertext_length_s = 0;
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_unified_header_serialize(unified_header, buffer, offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    psa_key_id_t const *write_key;
    psa_key_id_t const *iv_key;

    if (entity == CTLS_ENTITY_CLIENT) {
        write_key = phase == CTLS_PHASE_HANDSHAKE
                        ? &crypto->client_handshake_write_key
                        : &crypto->client_application_write_key;
        iv_key = phase == CTLS_PHASE_HANDSHAKE
                     ? &crypto->client_handshake_iv_key
                     : &crypto->client_application_iv_key;
    } else {
        write_key = phase == CTLS_PHASE_HANDSHAKE
                        ? &crypto->server_handshake_write_key
                        : &crypto->server_application_write_key;
        iv_key = phase == CTLS_PHASE_HANDSHAKE
                     ? &crypto->server_handshake_iv_key
                     : &crypto->server_application_iv_key;
    }

    result = ctls_encrypt(write_key,
                          iv_key,
                          &unified_header->sequence_number,
                          buffer,
                          unified_header->aad_length,
                          plaintext,
                          plaintext_length,
                          &buffer[unified_header->aad_length],
                          &ciphertext_length_s);
    if (result != CTLS_STATUS_SUCCESS) return result;

    *offset += (ctls_size_t) ciphertext_length_s;
    *ciphertext_length = ciphertext_length_s;

    return result;
}

ctls_status_t ctls_record_decrypt(ctls_record_t *record,
                                  uint8_t const *buffer,
                                  uint8_t *plaintext,
                                  ctls_size_t *plaintext_bytes_written,
                                  ctls_phase_t const phase,
                                  ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    ctls_crypto_t *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(plaintext);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(plaintext_bytes_written);
    CTLS_CHECK_NULL(hshk_data);

    ctls_size_t offset = 0;
    size_t plaintext_bytes_written_s = 0;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    /* epoch expansion reconstructs from 2 wire bits — needs our current
       epoch as base */
    record->unified_header.epoch = hshk_data->epoch;
    ctls_status_t result = ctls_unified_header_deserialize(&record->unified_header,
                                                           buffer,
                                                           &offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    /* Decrypt using the sender's write key — decryptor uses peer's keys */
    psa_key_id_t const *write_key;
    psa_key_id_t const *iv_key;
    if (entity == CTLS_ENTITY_CLIENT) {
        write_key = phase == CTLS_PHASE_HANDSHAKE
                        ? &crypto->client_handshake_write_key
                        : &crypto->client_application_write_key;
        iv_key = phase == CTLS_PHASE_HANDSHAKE
                     ? &crypto->client_handshake_iv_key
                     : &crypto->client_application_iv_key;
    } else {
        write_key = phase == CTLS_PHASE_HANDSHAKE
                        ? &crypto->server_handshake_write_key
                        : &crypto->server_application_write_key;
        iv_key = phase == CTLS_PHASE_HANDSHAKE
                     ? &crypto->server_handshake_iv_key
                     : &crypto->server_application_iv_key;
    }

    result = ctls_decrypt(write_key,
                          iv_key,
                          &record->unified_header.sequence_number,
                          buffer,
                          record->unified_header.aad_length,
                          &buffer[offset],
                          record->unified_header.length,
                          plaintext,
                          &plaintext_bytes_written_s);

    if (result != CTLS_STATUS_SUCCESS) return result;

    /* AEAD tag verified — header is authentic, accept the peer's epoch */
    hshk_data->epoch = record->unified_header.epoch;

    *plaintext_bytes_written = plaintext_bytes_written_s;
    return result;
}

/*
 * ClientHello record: PLAINTEXT type, profile id from the template. Body
 * built by the hsmg layer (fresh random, key share generation).
 */
ctls_status_t ctls_recd_client_hello_create(ctls_record_t *record) {
    ctls_template_t const *template = ctls_template_get();
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_STRUCT(hshk_data);

    ctls_status_t const result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->content_type = CTLS_RECD_CONTENT_TYPE_CTLS_HANDSHAKE;
    record->profile_id = template->profile_id;
    record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    record->record_body.handshake.sequence_number = hshk_data->sequence_number;

    return ctls_hsmg_client_hello_create(&record->record_body.handshake.
                                         handshake_message_body.client_hello);
}

/*
 * Parse a compact ClientHello record (server-side receive).
 *
 * DEFAULT wire framing (inverse of ctls_recd_client_hello_to_wire DEFAULT):
 *
 *     content_type(u8)
 *     | profile_id_length(u8)  = 0x04
 *     | profile_id(u32)
 *     | compact CH body (see ctls_hsmg_client_hello_to_struct)
 */
ctls_status_t ctls_recd_client_hello_to_struct(ctls_record_t *record,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(template);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint8_t content_type_u8 = 0;
    uint8_t profile_id_length_u8 = 0;

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &content_type_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    record->content_type = content_type_u8;

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &profile_id_length_u8);
    if (result != CTLS_STATUS_SUCCESS) return result; /* profile_id_length — always 4 */

    result = ctls_read_u32(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &record->profile_id);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    record->unified_header.sequence_number = 0;

    return ctls_hsmg_client_hello_to_struct(&record->record_body.handshake,
                                            buffer,
                                            offset);
}


/*
 * ClientHello record framing.
 *
 * DEFAULT (compact cTLS bytes sent on wire):
 *
 *     content_type(u8) | profile_id_length(u8) | profile_id(u32)
 *     | compact ClientHello body (see hsmg.c)
 *
 * TRANSCRIPT_HASH (TLS 1.3 record reconstruction, hashed only):
 *
 *     content_type(u8) | legacy protocol version(u16) = 0x0303
 *     | record_body_length(u16, backfilled) | TLS 1.3 ClientHello body
 */
ctls_status_t ctls_recd_client_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_record_t const *record,
                                             ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        if (sizeof(record->content_type) + *offset > CTLS_SIZE_WIRE_BUFFER)
            return CTLS_STATUS_BUFFER_OVERFLOW;

        result = ctls_write_u8(buffer, offset, record->content_type, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        if ((sizeof(record->profile_id) + sizeof(uint8_t)) + *offset >
            CTLS_SIZE_WIRE_BUFFER) return CTLS_STATUS_BUFFER_OVERFLOW;

        result = ctls_write_u8(buffer, offset, sizeof(record->profile_id), CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u32(buffer, offset, record->profile_id, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return ctls_hsmg_client_hello_to_wire(buffer,
                                              offset,
                                              &record->record_body.handshake,
                                              CTLS_WIRE_FORMAT_DEFAULT);
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        result = ctls_write_u8(buffer, offset, record->content_type, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_3,
                                CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_size_t record_body_length = *offset;
        *offset += 2;
        result = ctls_hsmg_client_hello_to_wire(buffer,
            offset,
            &record->record_body.handshake,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        result = ctls_write_u16(buffer, &record_body_length, *offset - record_body_length,
                                CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }
    return CTLS_STATUS_RECD_CH_INVALID_WIRE_FORMAT;
}

/*
 * Build a ServerHello record struct (server-side create), mirroring
 * ctls_recd_client_hello_create. Sets plaintext framing fields then
 * delegates body creation to ctls_hsmg_server_hello_create.
 */
ctls_status_t ctls_recd_server_hello_create(ctls_record_t *record) {
    ctls_template_t const *template = ctls_template_get();
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_STRUCT(hshk_data);

    ctls_status_t const result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->content_type = CTLS_RECD_CONTENT_TYPE_CTLS_HANDSHAKE;
    record->profile_id = template->profile_id;
    record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    record->record_body.handshake.sequence_number = hshk_data->sequence_number;

    return ctls_hsmg_server_hello_create(&record->record_body.handshake.
                                         handshake_message_body.server_hello);
}

/*
 * Parse a compact ServerHello record:
 *
 *     content_type(u8) | record_body_length(u16) | compact SH body
 *
 * PLAINTEXT record — arrives before keys exist.
 */
ctls_status_t ctls_recd_server_hello_to_struct(ctls_record_t *record,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint8_t content_type_u8 = 0;

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &content_type_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    record->content_type = content_type_u8;

    record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    record->unified_header.sequence_number = 0;

    result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &record->unified_header.length);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_server_hello_to_struct(&record->record_body.handshake,
                                            buffer,
                                            offset);
}

/*
 * ServerHello record, TRANSCRIPT_HASH only (client never sends SH):
 *
 *     content_type(u8) | legacy version(u16) = 0x0303
 *     | record_body_length(u16, backfilled) | TLS 1.3 ServerHello body
 */
ctls_status_t ctls_recd_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_record_t const *record,
                                             ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        /*
         * Compact ServerHello record (inverse of ctls_recd_server_hello_to_struct):
         *     content_type(u8) | record_body_length(u16, backfilled)
         *     | compact SH body (see ctls_hsmg_server_hello_to_wire DEFAULT)
         */
        result = ctls_write_u8(buffer, offset, record->content_type, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_size_t record_body_length = *offset;
        *offset += 2;
        result = ctls_hsmg_server_hello_to_wire(buffer,
            offset,
            &record->record_body.handshake,
            wire_format);
        if (result != CTLS_STATUS_SUCCESS) return result;

        result = ctls_write_u16(buffer, &record_body_length, *offset - record_body_length,
                                CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        return CTLS_STATUS_SUCCESS;
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        result = ctls_write_u8(buffer, offset, record->content_type, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_3,
                                CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_size_t record_body_length = *offset;
        *offset += 2;
        result = ctls_hsmg_server_hello_to_wire(buffer,
            offset,
            &record->record_body.handshake,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        result = ctls_write_u16(buffer, &record_body_length, *offset - record_body_length,
                                CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_RECD_SH_INVALID_WIRE_FORMAT;
}

/*
 * Build the combined server flight (EE + Certificate + CertificateVerify +
 * Finished) as a single encrypted record, mirroring ctls_recd_client_flight_create.
 * The unified header is stamped here; the body is serialized and encrypted by
 * ctls_recd_server_flight_to_wire (called from ctls_record_serialize).
 */
ctls_status_t ctls_recd_server_flight_create(ctls_record_t *record) {
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    record->content_type = CTLS_RECD_CONTENT_TYPE_CTLS_HANDSHAKE;
    /* Sequencing lives solely in the unified header for encrypted records. */

    result = ctls_unified_header_build(&record->unified_header, 0);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_server_flight_create(&record->record_body.handshake.
                                          handshake_message_body.server_flight);
}

/*
 * Combined server flight (cTLS combined message): one decrypt, then the
 * four hsmg parsers consume the body in order —
 * EncryptedExtensions | Certificate | CertificateVerify | Finished.
 */
ctls_status_t ctls_recd_server_flight_to_struct(ctls_record_t *record,
                                                uint8_t const *buffer) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);


    return ctls_hsmg_server_flight_to_struct(&record->record_body.handshake.
                                             handshake_message_body.server_flight,
                                             buffer);
}

/*
 * Server flight emit (transcript reconstruction on the client side):
 * unified header, then EE | Certificate | CertificateVerify | Finished
 * bodies in order.
 */
ctls_status_t ctls_recd_server_flight_to_wire(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_record_t *record,
                                              ctls_wire_format_t const wire_format,
                                              ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format != CTLS_WIRE_FORMAT_DEFAULT && wire_format !=
        CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) return CTLS_STATUS_RECD_SF_INVALID_WIRE_FORMAT;

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    result = ctls_hsmg_server_flight_to_wire(plaintext,
                                             &plaintext_offset,
                                             &record->record_body.handshake.
                                             handshake_message_body.server_flight,
                                             wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_write_u8(plaintext, &plaintext_offset, record->content_type,
                           CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_unified_header_length_update(&record->unified_header,
                                               (uint16_t) (
                                                   plaintext_offset +
                                                   CTLS_SIZE_AEAD_TAG));
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_size_t ciphertext_length = 0;
    return ctls_record_encrypt(buffer,
                               offset,
                               &record->unified_header,
                               plaintext,
                               plaintext_offset,
                               &ciphertext_length,
                               CTLS_PHASE_HANDSHAKE,
                               entity);
}


/*
 * Combined client flight (cTLS combined message): Certificate +
 * CertificateVerify + Finished in one encrypted record. Unified header
 * built here, stamping the current sequence number and epoch.
 */
ctls_status_t ctls_recd_client_flight_create(ctls_record_t *record) {
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    record->content_type = CTLS_RECD_CONTENT_TYPE_CTLS_HANDSHAKE;
    /* Sequencing lives solely in the unified header for encrypted records. */

    result = ctls_unified_header_build(&record->unified_header, 0);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_client_flight_create(&record->record_body.handshake.
                                          handshake_message_body.client_flight);
}

ctls_status_t ctls_recd_client_flight_to_struct(ctls_record_t *record,
                                                uint8_t const *buffer) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);


    return ctls_hsmg_client_flight_to_struct(&record->record_body.handshake.
                                             handshake_message_body.client_flight,
                                             buffer);
}

ctls_status_t ctls_recd_client_flight_to_wire(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_record_t *record,
                                              ctls_wire_format_t const wire_format,
                                              ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format != CTLS_WIRE_FORMAT_DEFAULT && wire_format !=
        CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) return CTLS_STATUS_RECD_SF_INVALID_WIRE_FORMAT;

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    result = ctls_hsmg_client_flight_to_wire(plaintext,
                                             &plaintext_offset,
                                             &record->record_body.handshake.
                                             handshake_message_body.client_flight,
                                             wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    // ciphertext (DTLS 1.3 unified record RFC 8446 §5.2
    // unified_header | Enc(hsmg_body ‖ content_type) | tag
    result = ctls_write_u8(plaintext, &plaintext_offset, record->content_type,
                           CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_unified_header_length_update(&record->unified_header,
                                               (uint16_t) (
                                                   plaintext_offset +
                                                   CTLS_SIZE_AEAD_TAG));
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_size_t ciphertext_length = 0;
    return ctls_record_encrypt(buffer,
                               offset,
                               &record->unified_header,
                               plaintext,
                               plaintext_offset,
                               &ciphertext_length,
                               CTLS_PHASE_HANDSHAKE,
                               entity);
}

ctls_status_t ctls_recd_application_data_deserialize(uint8_t const *buffer,
                                                     uint8_t *application_data,
                                                     ctls_size_t application_data_length,
                                                     ctls_entity_t const entity) {
    ctls_record_t *record = ctls_record_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_BUFFER(application_data);
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t const result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_record_decrypt(record,
                               buffer,
                               application_data,
                               &application_data_length,
                               CTLS_PHASE_APPLICATION_DATA,
                               entity);
}


ctls_status_t ctls_recd_application_data_serialize(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   uint8_t const *application_data,
                                                   ctls_size_t const
                                                   application_data_length,
                                                   ctls_entity_t const entity) {
    ctls_record_t *record = ctls_record_get();

    CTLS_CHECK_NULL_BUFFER(application_data);
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->content_type = CTLS_RECD_CONTENT_TYPE_APPLICATION_DATA;

    /* TLSInnerPlaintext (RFC 8446 §5.2): application_data || content_type,
     * encrypted together — mirrors the flight/alert to_wire functions. */
    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    result = ctls_write_bytes(plaintext, &plaintext_offset, application_data_length,
                              application_data, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_write_u8(plaintext, &plaintext_offset, record->content_type,
                           CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_unified_header_build(
            &record->unified_header, (uint16_t) (plaintext_offset + CTLS_SIZE_AEAD_TAG));
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_size_t ciphertext_length = 0;
    return ctls_record_encrypt(buffer,
                               offset,
                               &record->unified_header,
                               plaintext,
                               plaintext_offset,
                               &ciphertext_length,
                               CTLS_PHASE_APPLICATION_DATA,
                               entity);
}


ctls_status_t ctls_recd_alert_create(ctls_record_t *record,
                                     ctls_hsmg_alert_type_t const description,
                                     ctls_hsmg_alert_level_t const alert_level) {
    CTLS_CHECK_NULL_STRUCT(record);
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->content_type = CTLS_RECD_CONTENT_TYPE_ALERT;

    result = ctls_unified_header_build(&record->unified_header, 0);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_alert_create(&record->record_body.alert, description, alert_level);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_recd_alert_to_struct(ctls_record_t *record, uint8_t const *buffer) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0U;
    ctls_size_t offset = 0U;

    if (record->type == CTLS_RECORD_TYPE_PLAINTEXT) {
        result = ctls_hsmg_alert_to_struct(&record->record_body.alert, buffer, &offset);
        if (result != CTLS_STATUS_SUCCESS) return result;
    } else {
        result = ctls_record_decrypt(record,
                                     buffer,
                                     plaintext,
                                     &plaintext_offset,
                                     CTLS_PHASE_HANDSHAKE,
                                     CTLS_ENTITY_SERVER);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_recd_alert_to_wire(uint8_t *buffer,
                                      ctls_size_t *offset,
                                      ctls_record_t *record,
                                      ctls_entity_t const entity,
                                      ctls_phase_t const phase) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    result = ctls_hsmg_alert_to_wire(
            plaintext, &plaintext_offset, &record->record_body.alert);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (record->type == CTLS_RECORD_TYPE_PLAINTEXT) {
        result = ctls_write_u8(
                buffer, offset, record->content_type, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        result = ctls_write_u16(buffer, offset, plaintext_offset, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return ctls_write_bytes(
                buffer, offset, plaintext_offset, plaintext, CTLS_SIZE_WIRE_BUFFER);
    }

    if (record->type == CTLS_RECORD_TYPE_ENCRYPTED) {
        result = ctls_write_u8(plaintext, &plaintext_offset, record->content_type,
                               CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        result = ctls_unified_header_length_update(&record->unified_header,
                                                   (uint16_t) (
                                                       plaintext_offset +
                                                       CTLS_SIZE_AEAD_TAG));
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_size_t ciphertext_length = 0;
        return ctls_record_encrypt(buffer,
                                   offset,
                                   &record->unified_header,
                                   plaintext,
                                   plaintext_offset,
                                   &ciphertext_length,
                                   phase,
                                   entity);
    }


    return CTLS_STATUS_SUCCESS;
}
