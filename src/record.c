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
#include "ctls/hsmg.h"
#include "ctls/record.h"
#include "ctls/templates.h"

/*
 * Serialized header size = AAD size, from the config bits:
 * octet(1) + sequence(s_bit ? 2 : 1) + length(l_bit ? 2 : 0) — 2..5 bytes.
 * Stored in unified_header->aad_length. CID unsupported.
 */
ctls_status_t ctls_aad_length_calculate(ctls_unified_header_t *unified_header) {
    CTLS_CHECK_NULL_STRUCT(unified_header);

    if (unified_header->config_octet.c_bit != 0) return CTLS_STATUS_RECD_UNSUPPORTED_CID;

    unified_header->aad_length = 1U + (unified_header->config_octet.s_bit ? 2U : 1U) + (
                                     unified_header->config_octet.l_bit ? 2U : 1U);

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
    unified_header->config_octet.s_bit = (hshk_data->sequence_number > 0xFFu) ? 1u : 0u;
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

    if (unified_header->config_octet.c_bit != 0) return CTLS_STATUS_RECD_UNSUPPORTED_CID;

    if (unified_header->config_octet.s_bit != 0 && unified_header->config_octet.s_bit !=
        1) return CTLS_STATUS_RECD_INVALID_SEQ_LEN;

    uint8_t octet = CTLS_RECD_CONFIG_OCTET_FIXED_VALUE;
    if (unified_header->config_octet.c_bit) octet |= CTLS_RECD_CONFIG_OCTET_C_MASK;
    if (unified_header->config_octet.s_bit) octet |= CTLS_RECD_CONFIG_OCTET_S_MASK;
    if (unified_header->config_octet.l_bit) octet |= CTLS_RECD_CONFIG_OCTET_L_MASK;
    octet |= ctls_epoch_compress(&unified_header->epoch) &
            CTLS_RECD_CONFIG_OCTET_EPOCH_MASK;

    buffer[(*offset)++] = octet;

    if (unified_header->config_octet.s_bit == 0) {
        ctls_write_u8(buffer, offset, (uint8_t) unified_header->sequence_number);
    } else {
        ctls_write_u16(buffer, offset, unified_header->sequence_number);
    }

    if (unified_header->config_octet.l_bit == 1) {
        ctls_write_u16(buffer, offset, unified_header->length);
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

    uint8_t const first_part = buffer[(*offset)++];
    uint8_t const second_part = buffer[(*offset)++];

    unified_header->config_octet.c_bit =
            (first_part & CTLS_RECD_CONFIG_OCTET_C_MASK) != 0;
    unified_header->config_octet.s_bit = second_part;
    unified_header->config_octet.l_bit =
            (first_part & CTLS_RECD_CONFIG_OCTET_L_MASK) != 0;
    unified_header->config_octet.epoch = first_part & CTLS_RECD_CONFIG_OCTET_EPOCH_MASK;

    if (unified_header->config_octet.c_bit == 1) return CTLS_STATUS_RECD_UNSUPPORTED_CID;

    if (unified_header->config_octet.s_bit > 1 || unified_header->config_octet.s_bit < 0)
        return CTLS_STATUS_RECD_INVALID_SEQ_LEN;

    if (unified_header->config_octet.s_bit == 0) {
        unified_header->sequence_number = ctls_read_u8(buffer, offset);
    } else {
        unified_header->sequence_number = ctls_read_u16(buffer, offset);
    }
    if (unified_header->config_octet.l_bit == 1) {
        unified_header->length = ctls_read_u16(buffer, offset);
    }

    ctls_epoch_expand(unified_header->config_octet.epoch, &unified_header->epoch);

    return ctls_aad_length_calculate(unified_header);
}

/*
 * Record struct -> final wire bytes, dispatched on record type + message
 * type. PLAINTEXT (CH/SH) serializes straight into buffer. ENCRYPTED
 * flights serialize header into buffer and body into the plaintext scratch,
 * then encrypt inside their to_wire. On success consumes one sequence
 * number (see counter block above).
 */
ctls_status_t ctls_record_serialize(ctls_record_t const *record,
                                    uint8_t *buffer,
                                    ctls_size_t *offset) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    ctls_status_t result = ctls_wire_buffer_clear(buffer, offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (record->type == CTLS_RECORD_TYPE_PLAINTEXT) {
        switch (record->record_body.handshake.message_type) {
            case CTLS_HSMG_TYPE_CLIENT_HELLO:
                result = ctls_recd_client_hello_to_wire(buffer,
                                                        offset,
                                                        record,
                                                        CTLS_WIRE_FORMAT_DEFAULT);
                break;
            case CTLS_HSMG_TYPE_SERVER_HELLO:
                result = CTLS_STATUS_NOT_IMPLEMENTED;
                break;
            case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS:
            case CTLS_HSMG_TYPE_CERTIFICATE_REQUEST:
            case CTLS_HSMG_TYPE_CERTIFICATE:
            case CTLS_HSMG_TYPE_CERTIFICATE_VERIFY:
            case CTLS_HSMG_TYPE_FINISHED:
            case CTLS_HSMG_TYPE_CLIENT_FLIGHT:
            case CTLS_HSMG_TYPE_SERVER_FLIGHT:
                return CTLS_STATUS_RECD_INVALID_MSG_TYPE;
            default:
                return CTLS_STATUS_RECD_UNKNOWN_MSG_TYPE;
        }
    }
    if (record->type == CTLS_RECORD_TYPE_ENCRYPTED) {
        uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
        ctls_size_t plaintext_offset = 0;

        switch (record->record_body.handshake.message_type) {
            case CTLS_HSMG_TYPE_CLIENT_FLIGHT: {
                result = ctls_recd_client_flight_to_wire(buffer,
                                                         offset,
                                                         plaintext,
                                                         &plaintext_offset,
                                                         record,
                                                         CTLS_WIRE_FORMAT_DEFAULT);
            }
            break;
            case CTLS_HSMG_TYPE_SERVER_FLIGHT: {
                result = ctls_recd_server_flight_to_wire(buffer,
                                                         offset,
                                                         record,
                                                         CTLS_WIRE_FORMAT_DEFAULT);
            }
            break;
            case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS:
            case CTLS_HSMG_TYPE_CERTIFICATE_REQUEST:
            case CTLS_HSMG_TYPE_CERTIFICATE:
            case CTLS_HSMG_TYPE_CERTIFICATE_VERIFY:
            case CTLS_HSMG_TYPE_FINISHED: return CTLS_STATUS_RECD_INVALID_MSG_TYPE;
            default: return CTLS_STATUS_RECD_UNKNOWN_MSG_TYPE;
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
                                      uint8_t const *buffer) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    ctls_size_t offset = 0;

    result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    switch (hsmg_type) {
        case CTLS_HSMG_TYPE_CLIENT_HELLO:
            result = CTLS_STATUS_NOT_IMPLEMENTED;
            break;
        case CTLS_HSMG_TYPE_SERVER_HELLO:
            result = ctls_recd_server_hello_to_struct(record, buffer, &offset);
            break;
        case CTLS_HSMG_TYPE_SERVER_FLIGHT:
            result = ctls_recd_server_flight_to_struct(record, buffer);
            break;
        case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS:
        case CTLS_HSMG_TYPE_CERTIFICATE_REQUEST:
        case CTLS_HSMG_TYPE_CERTIFICATE:
        case CTLS_HSMG_TYPE_CERTIFICATE_VERIFY:
        case CTLS_HSMG_TYPE_FINISHED:
            result = CTLS_STATUS_RECD_INVALID_MSG_TYPE;
        default:
            result = CTLS_STATUS_RECD_UNKNOWN_MSG_TYPE;
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
                                  ctls_phase_t const phase) {
    ctls_crypto_t *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL_STRUCT(unified_header);

    size_t ciphertext_length_s = 0;
    ctls_status_t result = ctls_unified_header_serialize(unified_header, buffer, offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

#if CTLS_CLIENT
    result = ctls_encrypt(phase == CTLS_PHASE_HANDSHAKE
                              ? &crypto->client_handshake_write_key
                              : &crypto->client_application_write_key,
                          phase == CTLS_PHASE_HANDSHAKE
                              ? &crypto->client_handshake_iv_key
                              : &crypto->client_application_iv_key,
                          &unified_header->sequence_number,
                          buffer,
                          unified_header->aad_length,
                          plaintext,
                          plaintext_length,
                          &buffer[unified_header->aad_length],
                          &ciphertext_length_s);

#endif
#if CTLS_SERVER
    result = ctls_encrypt(phase == CTLS_PHASE_HANDSHAKE
                              ? &crypto->server_handshake_write_key
                              : &crypto->server_application_write_key,
                          phase == CTLS_PHASE_HANDSHAKE
                              ? &crypto->server_handshake_iv_key
                              : &crypto->server_application_iv_key,
                          &unified_header->sequence_number,
                          buffer,
                          unified_header->aad_length,
                          plaintext,
                          plaintext_length,
                          &buffer[unified_header->aad_length],
                          &ciphertext_length_s);
#endif

    if (result != CTLS_STATUS_SUCCESS) return result;
    *ciphertext_length = ciphertext_length_s;

    return result;
}

ctls_status_t ctls_record_decrypt(ctls_record_t *record,
                                  uint8_t const *buffer,
                                  uint8_t *plaintext,
                                  ctls_size_t *plaintext_bytes_written,
                                  ctls_phase_t const phase) {
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

#if CTLS_CLIENT
    result = ctls_decrypt(phase == CTLS_PHASE_HANDSHAKE
                              ? &crypto->client_handshake_write_key
                              : &crypto->client_application_write_key,
                          phase == CTLS_PHASE_HANDSHAKE
                              ? &crypto->client_handshake_iv_key
                              : &crypto->client_application_iv_key,
                          &record->unified_header.sequence_number,
                          buffer,
                          record->unified_header.aad_length,
                          &buffer[offset],
                          record->unified_header.length,
                          plaintext,
                          &plaintext_bytes_written_s);

#endif
#if CTLS_SERVER
    result = ctls_decrypt(phase == CTLS_PHASE_HANDSHAKE
                              ? &crypto->server_handshake_write_key
                              : &crypto->server_application_write_key,
                          phase == CTLS_PHASE_HANDSHAKE
                              ? &crypto->server_handshake_iv_key
                              : &crypto->server_application_iv_key,
                          &record->unified_header.sequence_number,
                          buffer,
                          record->unified_header.aad_length,
                          &buffer[offset],
                          record->unified_header.length,
                          plaintext,
                          &plaintext_bytes_written_s);

#endif

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

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t const result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->profile_id = template->profile_id;
    record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    record->record_body.handshake.message_type = CTLS_HSMG_TYPE_CLIENT_HELLO;
    record->record_body.handshake.sequence_number = 0;

    return ctls_hsmg_client_hello_create(&record->record_body.handshake);
}

ctls_status_t ctls_recd_client_hello_to_struct() {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}


/*
 * ClientHello record framing.
 *
 * DEFAULT (compact cTLS bytes sent on wire):
 *
 *     content_type(u8) | profile_id_length(u8) | profile_id(u8)
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

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        if (sizeof(record->content_type) + *offset > CTLS_SIZE_WIRE_BUFFER) return
                CTLS_STATUS_BUFFER_OVERFLOW;

        ctls_write_u8(buffer, offset, record->content_type);

        if ((sizeof(record->profile_id) + sizeof(uint8_t)) + *offset >
            CTLS_SIZE_WIRE_BUFFER) return CTLS_STATUS_BUFFER_OVERFLOW;

        ctls_write_u8(buffer, offset, sizeof(record->profile_id));
        ctls_write_u8(buffer, offset, record->profile_id);

        return ctls_hsmg_client_hello_to_wire(buffer,
                                              offset,
                                              &record->record_body.handshake,
                                              CTLS_WIRE_FORMAT_DEFAULT);
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, record->content_type);
        ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_3);

        ctls_size_t record_body_length = *offset;
        *offset += 2;
        ctls_status_t const result = ctls_hsmg_client_hello_to_wire(buffer,
            offset,
            &record->record_body.handshake,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u16(buffer, &record_body_length, *offset - record_body_length);

        return CTLS_STATUS_SUCCESS;
    }
    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}


ctls_status_t ctls_recd_server_hello_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
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

    record->content_type = ctls_read_u8(buffer, offset);
    record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    record->unified_header.sequence_number = 0;
    record->unified_header.length = ctls_read_u16(buffer, offset);

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

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, record->content_type);
        ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_3);

        ctls_size_t record_body_length = *offset;
        *offset += 2;
        ctls_status_t const result = ctls_hsmg_server_hello_to_wire(buffer,
            offset,
            &record->record_body.handshake,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u16(buffer, &record_body_length, *offset - record_body_length);

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_recd_encrypted_extensions_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

/*
 * Standalone encrypted-message receive path (EE / CertificateRequest /
 * Certificate / CertificateVerify / Finished all follow this pattern):
 * decrypt the record into a stack scratch buffer, then hand the body
 * plaintext to the hsmg-layer parser. Used when messages arrive as
 * individual records rather than a combined flight.
 */
ctls_status_t ctls_recd_encrypted_extensions_to_struct(ctls_record_t *record,
                                                       uint8_t const *buffer) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    ctls_status_t const result = ctls_record_decrypt(record,
                                                     buffer,
                                                     plaintext,
                                                     &plaintext_offset,
                                                     CTLS_PHASE_HANDSHAKE);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_encrypted_extensions_to_struct(&record->record_body.handshake,
                                                    plaintext);
}

/*
 * Standalone encrypted-message transcript form (same pattern for the next
 * four functions): unified header bytes, then the hsmg-layer message body
 * in TLS 1.3 reconstruction. Hashed only — DEFAULT path empty, the client
 * sends these messages only inside the combined client flight.
 */
ctls_status_t ctls_recd_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_record_t const *record,
                                                     ctls_wire_format_t const
                                                     wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_status_t const result =
                ctls_unified_header_serialize(&record->unified_header, buffer, offset);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return ctls_hsmg_encrypted_extensions_to_wire(buffer,
                                                      offset,
                                                      &record->record_body.handshake,
                                                      CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_recd_certificate_request_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

/* Decrypt + parse; rejected outright when the template disables mutual
 * auth (RFC 8446 §4.3.2 — CertificateRequest only when client auth wanted). */
ctls_status_t ctls_recd_certificate_request_to_struct(ctls_record_t *record,
                                                      uint8_t const *buffer) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_BUFFER(buffer);

    if (template->mutual_auth == 0) return CTLS_STATUS_RECD_NO_MUTUAL_AUTH;

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    ctls_status_t const result = ctls_record_decrypt(record,
                                                     buffer,
                                                     plaintext,
                                                     &plaintext_offset,
                                                     CTLS_PHASE_HANDSHAKE);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_certificate_request_to_struct(&record->record_body.handshake,
                                                   plaintext);
}

ctls_status_t ctls_recd_certificate_request_to_wire(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_record_t const *record,
                                                    ctls_wire_format_t const
                                                    wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_unified_header_serialize(&record->unified_header, buffer, offset);

        ctls_status_t const result = ctls_hsmg_certificate_request_to_wire(buffer,
            offset,
            &record->record_body.handshake,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_recd_certificate_create(ctls_record_t *record,
                                           ctls_entity_t const entity) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t const result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    record->record_body.handshake.message_type = CTLS_HSMG_TYPE_CERTIFICATE;


    return ctls_hsmg_certificate_create(&record->record_body.handshake, entity);
}

ctls_status_t ctls_recd_certificate_to_struct(ctls_record_t *record,
                                              uint8_t const *buffer) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    ctls_status_t const result = ctls_record_decrypt(record,
                                                     buffer,
                                                     plaintext,
                                                     &plaintext_offset,
                                                     CTLS_PHASE_HANDSHAKE);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_certificate_to_struct(&record->record_body.handshake, plaintext);
}

ctls_status_t ctls_recd_certificate_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_record_t const *record,
                                            ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_unified_header_serialize(&record->unified_header, buffer, offset);

        ctls_status_t const result = ctls_hsmg_certificate_to_wire(buffer,
            offset,
            &record->record_body.handshake,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_recd_certificate_verify_create(ctls_record_t *record,
                                                  ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(record);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_RECD_INVALID_ENTITY;

    ctls_status_t const result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    record->record_body.handshake.message_type = CTLS_HSMG_TYPE_CERTIFICATE_VERIFY;
    record->record_body.handshake.sequence_number = 0;

    return ctls_hsmg_certificate_verify_create(&record->record_body.handshake, entity);
}

ctls_status_t ctls_recd_certificate_verify_to_struct(ctls_record_t *record,
                                                     uint8_t const *buffer,
                                                     ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    ctls_status_t const result = ctls_record_decrypt(record,
                                                     buffer,
                                                     plaintext,
                                                     &plaintext_offset,
                                                     CTLS_PHASE_HANDSHAKE);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_certificate_verify_to_struct(&record->record_body.handshake,
                                                  plaintext,
                                                  entity);
}

ctls_status_t ctls_recd_certificate_verify_to_wire(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   ctls_record_t const *record,
                                                   ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_unified_header_serialize(&record->unified_header, buffer, offset);

        ctls_status_t const result = ctls_hsmg_certificate_verify_to_wire(buffer,
            offset,
            &record->record_body.handshake,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_recd_finished_create(ctls_record_t *record,
                                        ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(record);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_RECD_INVALID_ENTITY;

    ctls_status_t const result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    record->record_body.handshake.message_type = CTLS_HSMG_TYPE_FINISHED;
    record->record_body.handshake.sequence_number = 0;

    return ctls_hsmg_finished_create(&record->record_body.handshake, entity);
}

ctls_status_t ctls_recd_finished_to_struct(ctls_record_t *record,
                                           uint8_t const *buffer,
                                           ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    ctls_status_t const result = ctls_record_decrypt(record,
                                                     buffer,
                                                     plaintext,
                                                     &plaintext_offset,
                                                     CTLS_PHASE_HANDSHAKE);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_finished_to_struct(&record->record_body.handshake,
                                        plaintext,
                                        entity);
}

ctls_status_t ctls_recd_finished_to_wire(uint8_t *buffer,
                                         ctls_size_t *offset,
                                         ctls_record_t const *record,
                                         ctls_wire_format_t wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_unified_header_serialize(&record->unified_header, buffer, offset);

        ctls_status_t const result = ctls_hsmg_finished_to_wire(buffer,
            offset,
            &record->record_body.handshake,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}


ctls_status_t ctls_recd_server_flight_create(ctls_record_t *record) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
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

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t plaintext_offset = 0;

    ctls_status_t result = ctls_record_decrypt(record,
                                               buffer,
                                               plaintext,
                                               &plaintext_offset,
                                               CTLS_PHASE_HANDSHAKE);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_encrypted_extensions_to_struct(&record->record_body.handshake,
                                                      plaintext);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_to_struct(&record->record_body.handshake, plaintext);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_verify_to_struct(&record->record_body.handshake,
                                                    plaintext,
                                                    CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_finished_to_struct(&record->record_body.handshake,
                                        plaintext,
                                        CTLS_ENTITY_SERVER);
}

/*
 * Server flight emit (transcript reconstruction on the client side):
 * unified header, then EE | Certificate | CertificateVerify | Finished
 * bodies in order.
 */
ctls_status_t ctls_recd_server_flight_to_wire(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_record_t const *record,
                                              ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format != CTLS_WIRE_FORMAT_DEFAULT && wire_format !=
        CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;

    ctls_status_t result = ctls_unified_header_serialize(&record->unified_header,
                                                         buffer,
                                                         offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_encrypted_extensions_to_wire(buffer,
                                                    offset,
                                                    &record->record_body.handshake,
                                                    wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_to_wire(buffer,
                                           offset,
                                           &record->record_body.handshake,
                                           wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_verify_to_wire(buffer,
                                                  offset,
                                                  &record->record_body.handshake,
                                                  wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_finished_to_wire(buffer,
                                        offset,
                                        &record->record_body.handshake,
                                        wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return result;
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
    record->record_body.handshake.message_type = CTLS_HSMG_TYPE_CLIENT_FLIGHT;
    record->record_body.handshake.sequence_number = 0;

    result = ctls_unified_header_build(&record->unified_header, 0);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_create(&record->record_body.handshake,
                                          CTLS_ENTITY_CLIENT);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_verify_create(&record->record_body.handshake,
                                                 CTLS_ENTITY_CLIENT);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_finished_create(&record->record_body.handshake, CTLS_ENTITY_CLIENT);
}

ctls_status_t ctls_recd_client_flight_to_struct(ctls_record_t *record,
                                                uint8_t const *buffer) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

/*
 * Client flight emit. Two buffers: the unified header goes straight into
 * buffer (clear — it is the AAD), the three message bodies
 * (Certificate | CertificateVerify | Finished) accumulate in the plaintext
 * scratch, and ctls_record_encrypt appends AES-GCM(plaintext) | tag after
 * the header in buffer.
 */
ctls_status_t ctls_recd_client_flight_to_wire(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              uint8_t *plaintext,
                                              ctls_size_t *plaintext_bytes_written,
                                              ctls_record_t const *record,
                                              ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format != CTLS_WIRE_FORMAT_DEFAULT && wire_format !=
        CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;

    ctls_status_t result = ctls_unified_header_serialize(&record->unified_header,
                                                         buffer,
                                                         offset);
    if (result != CTLS_STATUS_SUCCESS) return result;


    result = ctls_hsmg_certificate_to_wire(plaintext,
                                           plaintext_bytes_written,
                                           &record->record_body.handshake,
                                           wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_verify_to_wire(plaintext,
                                                  plaintext_bytes_written,
                                                  &record->record_body.handshake,
                                                  wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_finished_to_wire(plaintext,
                                        plaintext_bytes_written,
                                        &record->record_body.handshake,
                                        wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_size_t ciphertext_length = 0;
    return ctls_record_encrypt(buffer,
                               offset,
                               &record->unified_header,
                               plaintext,
                               *plaintext_bytes_written,
                               &ciphertext_length,
                               CTLS_PHASE_HANDSHAKE);
}
