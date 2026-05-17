//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#ifndef CTLS_EXTENSIONS_H
#define CTLS_EXTENSIONS_H

#include <stdint.h>
#include "types.h"

struct ctls_hshk_buffer_block {
    uint8_t *buffer;
    ctls_size_t buffer_length;
};

struct ctls_extn_server_name_item {
    ctls_extn_host_name_type_t name_type;
    ctls_hshk_buffer_block_t server_name;
};
struct ctls_extn_server_name {
    ctls_data_form_t form;
    ctls_extn_type_t extension_type;
    union {
        ctls_extn_server_name_item_t parsed_list[CTLS_COUNT_SERVER_NAME];
        ctls_hshk_buffer_block_t opaque;
    };
};

struct ctls_extn_ocsp_status_request {
    // set these values to 0.
    ctls_hshk_buffer_block_t responder_id;
    ctls_hshk_buffer_block_t request_extensions;
};
struct ctls_extn_certificate_status_request_parsed {
    ctls_extn_certificate_status_type_t certificate_status_type;
    ctls_extn_ocsp_status_request_t ocsp_status_request;
};
struct ctls_extn_certificate_status_request {
    ctls_data_form_t form;
    ctls_extn_type_t extension_type;
    union {
        ctls_extn_certificate_status_request_parsed_t status_request;
        ctls_hshk_buffer_block_t opaque;
    };
};

// Application layer protocol negotiation
struct ctls_extn_alpn {
    ctls_data_form_t form;
    ctls_extn_type_t extension_type;
    union {
        ctls_hshk_buffer_block_t alpn_list[CTLS_COUNT_ALPN];
        ctls_hshk_buffer_block_t opaque;
    };
};

struct ctls_extn_supported_groups {
    ctls_data_form_t form;
    ctls_extn_type_t extension_type;
    union {
        ctls_extn_dhe_group_type_t supported_group;
        ctls_hshk_buffer_block_t opaque;
    };
};
struct ctls_extn_supported_version {
    ctls_data_form_t form;
    ctls_extn_type_t extension_type;
    union {
        ctls_hsmg_protocol_version_t version;
        ctls_hshk_buffer_block_t opaque;
    };
};
struct ctls_extn_signature_algorithm {
    ctls_data_form_t form;
    ctls_extn_type_t extension_type;
    union {
        ctls_extn_signature_algorithm_type_t signature_algorithm;
        ctls_hshk_buffer_block_t opaque;
    };
};
struct ctls_extn_key_share {
    ctls_data_form_t form;
    ctls_extn_type_t extension_type;
    union {
        ctls_hshk_buffer_block_t key_share;
        ctls_hshk_buffer_block_t opaque;
    };
};

struct ctls_extn_certificate_authorities {
    ctls_data_form_t form;
    ctls_extn_type_t extension_type;
    union {
        ctls_hshk_buffer_block_t opaque;
        ctls_hshk_buffer_block_t distinguished_name;
    };
};

struct ctls_extn_signed_certificate_timestamp_parsed {
    ctls_extn_signature_algorithm_type_t signature_algorithm;
    ctls_extn_sct_version_t sct_version;
    uint8_t log_id[CTLS_SIZE_SCT_LOG_ID];
    uint64_t timestamp;
    ctls_extn_sct_entry_type_t entry_type;
    uint8_t *certificate;
    uint8_t extensions;
    uint8_t *signed_bytes;
    ctls_size_t signed_bytes_length;
};
struct ctls_extn_signed_certificate_timestamp {
    ctls_data_form_t form;
    ctls_extn_type_t extension_type;
    union {
        ctls_hshk_buffer_block_t opaque;
        ctls_extn_signed_certificate_timestamp_parsed_t signed_certificate_timestamp;
    };
};

struct ctls_extn_client_hello {
    ctls_extn_server_name_t server_name;
    ctls_max_fragment_length_t maximum_fragment_length;
    ctls_extn_certificate_status_request_t certificate_status_request;
    ctls_extn_supported_groups_t supported_groups;
    ctls_extn_signature_algorithm_t signature_algorithm;
    ctls_extn_heartbeat_mode_t heartbeat_mode;
    ctls_extn_alpn_t alpn;
    ctls_extn_signed_certificate_timestamp_t signed_certificate_timestamp;
    ctls_extn_certificate_type_t client_certificate_type;
    ctls_extn_certificate_type_t server_certificate_type;
    ctls_extn_supported_version_t supported_versions;
    ctls_extn_psk_key_exchange_mode_t psk_key_exchange_modes;
    ctls_extn_certificate_authorities_t certificate_authorities;
    ctls_extn_post_handshake_auth_t post_handshake_auth;
    ctls_extn_signature_algorithm_t signature_algorithm_cert;
    ctls_extn_key_share_t key_share_entity;
};

struct ctls_extn_server_hello {
    ctls_extn_supported_version_t supported_versions;
    ctls_extn_key_share_t key_share_entity;
};

struct ctls_extn_encrypted_extensions {
    ctls_extn_server_name_t server_name;
    ctls_max_fragment_length_t maximum_fragment_length;
    ctls_extn_supported_groups_t supported_groups;
    ctls_extn_heartbeat_mode_t heartbeat_mode;
    ctls_extn_alpn_t alpn;
    ctls_extn_certificate_type_t client_certificate_type;
    ctls_extn_certificate_type_t server_certificate_type;
};

struct ctls_extn_certificate_request {
    ctls_extn_certificate_status_request_t certificate_status_request;
    ctls_extn_signature_algorithm_t signature_algorithm;
    ctls_extn_signed_certificate_timestamp_t signed_certificate_timestamp;
    ctls_extn_certificate_authorities_t certificate_authorities;
    ctls_extn_signature_algorithm_type_t signature_algorithm_cert;
};

struct ctls_extn_certificate {
    ctls_extn_certificate_status_request_t certificate_status_request;
    ctls_extn_signed_certificate_timestamp_t signed_certificate_timestamp;
};

ctls_op_status_t ctls_extn_client_hello_create(
    ctls_extn_client_hello_t *client_hello_extensions,
    ctls_template_t const *template,
    ctls_hshk_data_t *hshk_data,
    ctls_crypto_t const *crypto);
ctls_op_status_t ctls_extn_client_hello_to_struct();
ctls_op_status_t ctls_extn_client_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_extn_client_hello_t const *
                                                client_hello_extensions,
                                                ctls_template_t const *template,
                                                ctls_wire_format_t wire_format);


ctls_op_status_t ctls_extn_server_hello_create(ctls_hsmg_server_hello_t *server_hello,
                                               ctls_template_t const *template);
ctls_op_status_t ctls_extn_server_hello_to_struct(
    ctls_extn_server_hello_t *server_hello_extensions,
    ctls_template_t const *template,
    ctls_hshk_data_t *hshk_data,
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_size_t buffer_size);
ctls_op_status_t ctls_extn_server_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_extn_server_hello_t const *
                                                server_hello_extensions,
                                                ctls_wire_format_t wire_format);


ctls_op_status_t ctls_extn_encrypted_extensions_create(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions,
    ctls_template_t const *template);
ctls_op_status_t ctls_extn_encrypted_extensions_to_struct(
    ctls_extn_encrypted_extensions_t *encrypted_extensions,
    ctls_template_t const *template,
    ctls_size_t *offset);
ctls_op_status_t ctls_extn_encrypted_extensions_to_wire(uint8_t *buffer,
                                                        ctls_size_t *offset,
                                                        ctls_extn_encrypted_extensions_t
                                                        const *encrypted_extensions,
                                                        ctls_wire_format_t wire_format);

ctls_op_status_t ctls_extn_certificate_request_create(void);
ctls_op_status_t ctls_extn_certificate_request_to_struct(
    ctls_extn_certificate_request_t *certificate_request_extensions,
    ctls_template_t const *template,
    ctls_size_t *offset);
ctls_op_status_t ctls_extn_certificate_request_to_wire(void);


#endif
