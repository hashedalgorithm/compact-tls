#ifndef CTLS_INTERNAL_H
#define CTLS_INTERNAL_H

#include <stdint.h>
#include <psa/crypto.h>
#include "types.h"

/* ------------------------------------------------------------------ */
/*  MACROS                                                            */
/* ------------------------------------------------------------------ */

#define CTLS_CHECK_NULL(pointer)                                    \
    do {                                                            \
        if ((pointer) == NULL)                                      \
            return (ctls_op_status_t) {                             \
                        .source = CTLS_ERROR_SOURCE_INTERNAL,       \
                        .code = CTLS_OP_STATUS_FAIL,                \
                        .external_code = CTLS_OP_STATUS_FAIL,       \
                    };                                              \
    } while (0)

#define CTLS_CHECK_BOUNDS(offset, size, limit)                      \
    do {                                                            \
        if ((offset) + (size) > (limit))                            \
            return (ctls_op_status_t) {                             \
                        .source = CTLS_ERROR_SOURCE_INTERNAL,       \
                        .code = CTLS_OP_STATUS_OVERFLOW,            \
                        .external_code = CTLS_OP_STATUS_OVERFLOW,   \
                    };                                              \
    } while (0)

/* ------------------------------------------------------------------ */
/*  DEFINITIONS                                                       */
/* ------------------------------------------------------------------ */

struct ctls_recd_config_octet {
    uint8_t c_bit; // connection_id
    uint8_t s_bit; // sequence_number
    uint8_t l_bit; // length
    uint8_t epoch;
};

// Extensions

/*
 * TODO
 *
 * Server Name
    struct ctls_extn_host_name {
        uint8_t name[32];
        uint8_t name_length;
    };
    struct ctls_extn_server_name {
        ctls_extn_host_name_type_t name;
        ctls_extn_host_name_t server_name;
    };
    struct ctls_extn_server_name_list {
        ctls_extn_server_name_t server_name;
        uint8_t count;
    };

    struct ctls_extn_certificate_status_request {};
    struct ctls_extn_srtp_data {
    };
    struct ctls_extn_use_srtp {
        ctls_extn_srtp_protection_profile_t srtp_protection_profile;
        uint8_t srtp_mki[255];
    };
*/


// CLIENT HELLO

struct ctls_extn_supported_groups {
    ctls_extn_type_t extension_type;
    ctls_extn_dhe_group_type_t supported_group;
};
struct ctls_extn_supported_version {
    ctls_extn_type_t extension_type;
    uint16_t version;
};
struct ctls_extn_signature_algorithm {
    ctls_extn_type_t extension_type;
    ctls_extn_signature_algorithm_type_t signature_algorithm;
};
struct ctls_extn_key_share {
    ctls_extn_type_t extension_type;
    ctls_extn_key_share_t key_share;
};

struct ctls_hsmg_extensions {
    ctls_extn_supported_groups_t supported_groups;
    ctls_extn_supported_version_t supported_versions;
    ctls_extn_signature_algorithm_t signature_algorithm;
    ctls_extn_key_share_t key_share_entity;
};
struct ctls_hshk_client_hello {
    ctls_hsmg_protocol_version_t protocol_version;
    ctls_hsmg_random_t random;
    uint8_t legacy_session_id;
    ctls_hsmg_cipher_suite_type_t cipher_suite;
    uint8_t legacy_compression_methods;
    ctls_hsmg_extensions_t extensions;
};

// SERVER HELLO

struct ctls_hsmg_server_hello {
    ctls_hsmg_random_t random;
    ctls_extn_key_share_t key_share;
};
struct ctls_hsmg_encrypted_extensions {
    uint8_t extensions[];
};
struct ctls_hsmg_certificate {
};
struct ctls_hsmg_certificate_verify {
    uint8_t signature[CTLS_WIRE_SIGNATURE];
};
struct ctls_hsmg_finished {
    int8_t verify_data[CTLS_WIRE_VERIFY_DATA];
};
struct ctls_hsmg_application_data {
    uint8_t *payload;
    uint16_t payload_length;
};
struct ctls_hsmg_alert {
    uint8_t level;
    uint8_t description;
};

typedef union {
    ctls_hsmg_client_hello_t client_hello;
    ctls_hsmg_server_hello_t server_hello;
    ctls_hsmg_encrypted_extensions_t encrypted_extensions;
    ctls_hsmg_certificate_t certificate;
    ctls_hsmg_certificate_verify_t certificate_verify;
    ctls_hsmg_finished_t finished;
    ctls_hsmg_application_data_t application_data;
    ctls_hsmg_alert_t alert;
} ctls_hsmg_body_t;

struct ctls_handshake_message {
    ctls_hsmg_type_t message_type;
    uint16_t sequence_number;
    ctls_hsmg_body_t handshake_message_body;
};

struct ctls_record {
    /* For Client Hello and Server Hello */
    uint8_t content_type;
    uint8_t template_id;
    /* Except for Client Hello and Server Hello */

    ctls_record_type_t type; // For internal reference

    /* Except for Client Hello and Server Hello */
    ctls_recd_config_octet_t config_octet;
    // To implement later when there is a scenario where UDP source address change
    // uint8_t connection_id;
    uint16_t sequence_number;
    uint16_t length;
    /* Except for Client Hello and Server Hello */

    ctls_handshake_message_t record_body;
};

struct ctls_op_status {
    ctls_op_status_code_t code;
    ctls_error_source_t source;
    uint16_t external_code;
};

struct ctls_tmpl_dhe_group {
    uint16_t length;
    ctls_extn_dhe_group_type_t dhe_group;
};
struct ctls_tmpl_signature_algorithm {
    uint16_t length;
    ctls_extn_signature_algorithm_type_t signature_algorithm;
};
struct ctls_tmpl_predefined_extensions {
    uint8_t server_name;
};
struct ctls_tmpl_extension {
    ctls_tmpl_predefined_extensions_t predefined_extensions;
    ctls_tmpl_expected_extensions_t expected_extensions;
    ctls_tmpl_self_delimiting_extensions_t self_delimiting_extensions;
    uint16_t allow_additional;
};

struct ctls_tmpl_extensions {
    ctls_tmpl_extension_t client_hello_extension;
    ctls_tmpl_extension_t server_hello_extension;
    ctls_tmpl_extension_t encrypted_extension;
    ctls_tmpl_extension_t certificate_request_extension;
};

struct ctls_template {
    uint8_t profile_id;
    uint16_t ctls_version;
    ctls_hsmg_protocol_version_t protocol_version;
    ctls_hsmg_cipher_suite_type_t cipher_suite;
    ctls_tmpl_dhe_group_t dhe_group;
    ctls_tmpl_signature_algorithm_t signature_algorithm;
    uint16_t random;
    uint8_t mutual_auth;
    uint8_t handshake_framing;
    ctls_tmpl_extensions_t extensions;
};

extern struct ctls_template ctls_templates[];

struct ctls_record_header {
    uint8_t content_type;
    uint64_t sequence_number;
    uint16_t length;
};


struct ctls_transcript_hash {
    uint8_t hash[CTLS_SIZE_TRANSCRIPT_HASH];
    psa_hash_operation_t hash_operator;
    uint64_t offset;
};

struct ctls_transport {
    ctls_recd_send recd_send;
    ctls_recd_receive recd_receive;
};

struct ctls_context {
    ctls_template_t *template;
    ctls_transcript_hash_t transcript_hash;
    ctls_hshk_state_t state;
    ctls_transport_t transport;
    uint64_t sequence_number;
    ctls_record_t record;
};


ctls_op_status_t ctls_clear_record_buffer(ctls_record_t *record_buffer);

ctls_op_status_t ctls_validate_template(ctls_template_t const *template);

ctls_op_status_t ctls_handshake(ctls_context_t *context);

ctls_op_status_t ctls_build_ctls_record(ctls_context_t *context,
                                        ctls_record_type_t type);
ctls_op_status_t ctls_build_ctls_record_client_hello(
    ctls_context_t *context);
ctls_op_status_t ctls_build_ctls_record_server_hello(
    ctls_context_t *context);
ctls_op_status_t ctls_build_record_encrypted_extensions(
    ctls_context_t *context);
ctls_op_status_t ctls_build_record_certificate(
    ctls_context_t *context);
ctls_op_status_t ctls_build_record_certificate_verify(
    ctls_context_t *context);
ctls_op_status_t
ctls_build_record_finished(ctls_context_t *context);
ctls_op_status_t ctls_compute_transcript_hash(
    uint8_t *transaction_hash);

ctls_op_status_t ctls_record_serialize(ctls_record_t const *record,
                                       uint8_t *buffer,
                                       size_t buffer_size,
                                       size_t *buffer_length);
ctls_op_status_t ctls_record_deserialize(ctls_record_t const *record,
                                         uint8_t *buffer,
                                         size_t buffer_length);

// Crypto
ctls_op_status_t ctls_generate_ephemeral_public_key(
    uint8_t *buffer, size_t buffer_length);
ctls_op_status_t ctls_generate_random(uint8_t *buffer);


#endif
