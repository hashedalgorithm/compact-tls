//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#ifndef CTLS_EXTENSIONS_H
#define CTLS_EXTENSIONS_H

#include <stdint.h>
#include "types.h"

typedef enum {
    CTLS_HELPER_IS_ONE_BYTE = 0,
    CTLS_HELPER_IS_TWO_BYTE = 1
} ctls_helper_is_one_byte_t;

typedef enum {
    CTLS_HELPER_ENTITY_OWNERSHIP_CLIENT = 0,
    CTLS_HELPER_ENTITY_OWNERSHIP_SERVER,
} ctls_helper_entity_ownership_t;

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
    uint8_t list_count;
    union {
        ctls_extn_server_name_item_t server_name_list[CTLS_COUNT_SERVER_NAME];
        ctls_hshk_buffer_block_t opaque;
    };
};

struct ctls_extn_ocsp_status_request {
    // set these values to 0.
    uint8_t responder_id;
    uint8_t request_extensions;
};
struct ctls_extn_certificate_status_request_parsed {
    ctls_extn_certificate_status_type_t certificate_status_type;
    ctls_extn_ocsp_status_request_t ocsp_status_request;
};
struct ctls_extn_certificate_status_request {
    ctls_data_form_t form;
    union {
        ctls_extn_certificate_status_request_parsed_t status_request;
        ctls_hshk_buffer_block_t opaque;
    };
};
struct ctls_extn_alpn_protocol_name {
    uint8_t protocol_name_length;
    uint8_t protocol_name[CTLS_SIZE_MAX_ALPN_PROTOCOL_NAME];
};

// Application layer protocol negotiation
struct ctls_extn_alpn {
    ctls_data_form_t form;
    uint8_t list_count;
    union {
        ctls_extn_alpn_protocol_name_t alpn_list[CTLS_COUNT_ALPN];
        ctls_hshk_buffer_block_t opaque;
    };
};


struct ctls_extn_certificate_authorities {
    ctls_data_form_t form;
    ctls_extn_type_t extension_type;
    uint8_t distinguished_name_length;
    union {
        ctls_hshk_buffer_block_t opaque;
        uint8_t distinguished_name[CTLS_SIZE_MAX_DISTINGUISHED_NAME];
    };
};

struct ctls_extn_signed_certificate_timestamp_parsed {
    ctls_extn_sct_version_t sct_version;
    uint8_t log_id[CTLS_SIZE_SCT_LOG_ID];
    uint64_t timestamp;
    uint8_t extensions;
    ctls_extn_sct_entry_type_t entry_type;
    ctls_extn_sct_signature_type_t signature_algorithm;
    ctls_hshk_buffer_block_t certificate;
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
    ctls_extn_max_fragment_length_t maximum_fragment_length;
    ctls_extn_certificate_status_request_t certificate_status_request;
    ctls_extn_supported_group_t supported_groups;
    ctls_extn_signature_algorithm_cert_t signature_algorithm;
    ctls_extn_heartbeat_mode_t heartbeat_mode;
    ctls_extn_alpn_t alpn;
    ctls_extn_signed_certificate_timestamp_t signed_certificate_timestamp;
    ctls_extn_certificate_type_t client_certificate_type;
    ctls_extn_certificate_type_t server_certificate_type;
    ctls_extn_supported_version_t supported_versions;
    ctls_extn_psk_key_exchange_mode_t psk_key_exchange_modes;
    ctls_extn_certificate_authorities_t certificate_authorities;
    ctls_extn_post_handshake_auth_t post_handshake_auth;
    ctls_extn_signature_algorithm_cert_t signature_algorithm_cert;
    ctls_extn_key_share_t key_share_entity;
};

struct ctls_extn_server_hello {
    ctls_extn_supported_version_t supported_versions;
    ctls_extn_key_share_t key_share_entity;
};

struct ctls_extn_encrypted_extensions {
    ctls_extn_server_name_t server_name;
    ctls_extn_max_fragment_length_t maximum_fragment_length;
    ctls_extn_supported_group_t supported_groups;
    ctls_extn_heartbeat_mode_t heartbeat_mode;
    ctls_extn_alpn_t alpn;
    ctls_extn_certificate_type_t client_certificate_type;
    ctls_extn_certificate_type_t server_certificate_type;
};

struct ctls_extn_certificate_request {
    ctls_extn_certificate_status_request_t certificate_status_request;
    ctls_extn_signature_algorithm_cert_t signature_algorithm;
    ctls_extn_signed_certificate_timestamp_t signed_certificate_timestamp;
    ctls_extn_certificate_authorities_t certificate_authorities;
    ctls_extn_signature_algorithm_cert_t signature_algorithm_cert;
};

struct ctls_extn_certificate {
    ctls_extn_certificate_status_request_t certificate_status_request;
    ctls_extn_signed_certificate_timestamp_t signed_certificate_timestamp;
};

ctls_op_status_t ctls_extn_enum_deserialize(void const *source,
                                            void *destination,
                                            ctls_helper_is_one_byte_t isOneByte);
ctls_op_status_t ctls_extn_enum_serialize(uint8_t *buffer,
                                          ctls_size_t *offset,
                                          ctls_extn_type_t extn_type,
                                          ctls_helper_is_one_byte_t isOneByte,
                                          uint16_t value);
ctls_op_status_t ctls_extn_server_name_deserialize(uint8_t *buffer,
                                                   ctls_size_t const *buffer_length,
                                                   ctls_data_form_t form,
                                                   ctls_extn_server_name_t *server_name);
ctls_op_status_t ctls_extn_server_name_serialize(uint8_t *buffer,
                                                 ctls_size_t *offset,
                                                 ctls_extn_server_name_t const *
                                                 server_name);

ctls_op_status_t ctls_extn_max_fragment_length_deserialize(
    ctls_extn_max_fragment_length_t const *source,
    ctls_extn_max_fragment_length_t *max_fragment_length);
ctls_op_status_t ctls_extn_max_fragment_length_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_max_fragment_length_t const *max_fragment_length);

ctls_op_status_t ctls_extn_certificate_status_request_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t form,
    ctls_extn_certificate_status_request_t *certificate_status_request);
ctls_op_status_t ctls_extn_certificate_status_request_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_certificate_status_request_t const *certificate_status_request);

ctls_op_status_t ctls_extn_supported_groups_deserialize(
    ctls_extn_supported_group_t const *source,
    ctls_extn_supported_group_t *supported_group);
ctls_op_status_t ctls_extn_supported_groups_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_supported_group_t const *supported_groups);

ctls_op_status_t ctls_extn_signature_algorithm_deserialize(
    ctls_extn_signature_algorithm_t const *source,
    ctls_extn_signature_algorithm_t *signature_algorithm);
ctls_op_status_t ctls_extn_signature_algorithm_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signature_algorithm_t const *signature_algorithm);

ctls_op_status_t ctls_extn_signature_algorithm_cert_deserialize(
    ctls_extn_signature_algorithm_t const *source,
    ctls_extn_signature_algorithm_t *signature_algorithm_cert);
ctls_op_status_t ctls_extn_signature_algorithm_cert_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signature_algorithm_t const *signature_algorithm_cert);

ctls_op_status_t ctls_extn_heartbeat_mode_deserialize(
    ctls_extn_heartbeat_mode_t const *source,
    ctls_extn_heartbeat_mode_t *heartbeat_mode);
ctls_op_status_t ctls_extn_heartbeat_mode_serialize(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_extn_heartbeat_mode_t const *
                                                    heartbeat_mode);

ctls_op_status_t ctls_extn_alpn_deserialize(uint8_t *buffer,
                                            ctls_size_t const *buffer_length,
                                            ctls_data_form_t form,
                                            ctls_extn_alpn_t *alpn);
ctls_op_status_t ctls_extn_alpn_serialize(uint8_t *buffer,
                                          ctls_size_t *offset,
                                          ctls_extn_alpn_t const *alpn);

ctls_op_status_t ctls_extn_signed_certificate_timestamp_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t form,
    ctls_extn_signed_certificate_timestamp_t *signed_certificate_timestamp);
ctls_op_status_t ctls_extn_signed_certificate_timestamp_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signed_certificate_timestamp_t const *signed_certificate_timestamp);

ctls_op_status_t ctls_extn_client_certificate_type_deserialize(
    ctls_extn_client_certificate_type_t const *source,
    ctls_extn_client_certificate_type_t *client_certificate_type);
ctls_op_status_t ctls_extn_client_certificate_type_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_client_certificate_type_t const *client_certificate_type);

ctls_op_status_t ctls_extn_server_certificate_type_deserialize(
    ctls_extn_server_certificate_type_t const *source,
    ctls_extn_server_certificate_type_t *server_certificate_type);
ctls_op_status_t ctls_extn_server_certificate_type_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_server_certificate_type_t const *server_certificate_type);

ctls_op_status_t ctls_extn_supported_versions_deserialize(
    ctls_extn_supported_version_t const *source,
    ctls_extn_supported_version_t *supported_versions);
ctls_op_status_t ctls_extn_supported_versions_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_supported_version_t const *supported_versions);

ctls_op_status_t ctls_extn_psk_key_exchange_modes_deserialize(
    ctls_extn_psk_key_exchange_mode_t const *source,
    ctls_extn_psk_key_exchange_mode_t *psk_key_exchange_modes);
ctls_op_status_t ctls_extn_psk_key_exchange_modes_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_psk_key_exchange_mode_t const *psk_key_exchange_modes);

ctls_op_status_t ctls_extn_certificate_authorities_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t form,
    ctls_extn_certificate_authorities_t *certificate_authorities);
ctls_op_status_t ctls_extn_certificate_authorities_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_certificate_authorities_t const *certificate_authorities);

ctls_op_status_t ctls_extn_post_handshake_auth_deserialize(
    ctls_extn_post_handshake_auth_t const *source,
    ctls_extn_post_handshake_auth_t *post_handshake_auth);
ctls_op_status_t ctls_extn_post_handshake_auth_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_post_handshake_auth_t const *post_handshake_auth);

ctls_op_status_t ctls_extn_key_share_deserialize(uint8_t *buffer,
                                                 ctls_size_t *offset,
                                                 ctls_helper_entity_ownership_t
                                                 entity_ownership,
                                                 ctls_extn_key_share_t key_share);
ctls_op_status_t ctls_extn_key_share_serialize(uint8_t *buffer,
                                               ctls_size_t *offset,
                                               ctls_wire_format_t wire_format,
                                               ctls_extn_key_share_t key_share);

ctls_op_status_t ctls_extn_client_hello_create(
    ctls_extn_client_hello_t *client_hello_extensions);
ctls_op_status_t ctls_extn_client_hello_to_struct();
ctls_op_status_t ctls_extn_client_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_extn_client_hello_t const *
                                                client_hello_extensions,
                                                ctls_wire_format_t wire_format);


ctls_op_status_t ctls_extn_server_hello_create(void);
ctls_op_status_t ctls_extn_server_hello_to_struct(
    ctls_extn_server_hello_t *server_hello_extensions,
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_size_t buffer_size);
ctls_op_status_t ctls_extn_server_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_extn_server_hello_t const *
                                                server_hello_extensions,
                                                ctls_wire_format_t wire_format);


ctls_op_status_t ctls_extn_encrypted_extensions_create(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions);
ctls_op_status_t ctls_extn_encrypted_extensions_to_struct(
    ctls_extn_encrypted_extensions_t *encrypted_extensions);
ctls_op_status_t ctls_extn_encrypted_extensions_to_wire(uint8_t *buffer,
                                                        ctls_size_t *offset,
                                                        ctls_extn_encrypted_extensions_t
                                                        const *encrypted_extensions,
                                                        ctls_wire_format_t wire_format);

ctls_op_status_t ctls_extn_certificate_request_create(void);
ctls_op_status_t ctls_extn_certificate_request_to_struct(
    ctls_extn_certificate_request_t *certificate_request_extensions);
ctls_op_status_t ctls_extn_certificate_request_to_wire(uint8_t *buffer,
                                                       ctls_size_t *offset,
                                                       ctls_extn_certificate_request_t
                                                       const *certificate_request,
                                                       ctls_wire_format_t wire_format);



#endif
