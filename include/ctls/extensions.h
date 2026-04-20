//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#ifndef CTLS_EXTENSIONS_H
#define CTLS_EXTENSIONS_H

#include <stdint.h>
#include "types.h"

struct ctls_extn_server_name {
    ctls_extn_host_name_type_t name_type;
    uint8_t server_name[CTLS_WIRE_SERVER_NAME];
};
struct ctls_extn_server_name_list {
    ctls_extn_server_name_t server_name;
};

struct ctls_extn_ocsp_status_request {
    // set these values to 0.
    uint8_t responder_id;
    uint8_t request_extensions;
};
struct ctls_extn_certificate_status_request {
    ctls_extn_certificate_status_type_t certificate_status_type;
    ctls_extn_ocsp_status_request_t ocsp_status_request;
};

// Application layer protocol negotiation
struct ctls_extn_alpn {
    ctls_extn_alpn_list_t alpn_list;
};

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

struct ctls_extn_client_hello {
    ctls_extn_supported_groups_t supported_groups;
    ctls_extn_supported_version_t supported_versions;
    ctls_extn_signature_algorithm_t signature_algorithm;
    ctls_extn_key_share_t key_share_entity;
    ctls_extn_server_name_t server_name;
    ctls_extn_maximum_fragment_length_t maximum_fragment_length;
    ctls_extn_certificate_status_request_t certificate_status_request;
    ctls_extn_heartbeat_type_t heartbeat_type;
    ctls_extn_alpn_list_t alpn_list;
    ctls_extn_certificate_type_t client_certificate_type;
    ctls_extn_certificate_type_t server_certificate_type;
    ctls_extn_psk_key_exchange_mode_t psk_key_exchange_modes;
    ctls_extn_post_handshake_auth_t post_handshake_auth;
    ctls_extn_signature_algorithm_type_t signature_algorithm_cert;
};


ctls_op_status_t ctls_extn_server_name_create(
    ctls_extn_server_name_t *server_name);
ctls_op_status_t ctls_extn_server_name_to_wire(uint8_t *buffer, size_t *offset,
                                               ctls_wire_format_t wire_format);
ctls_op_status_t ctls_extn_server_name_to_struct(
    uint8_t *buffer, size_t *offset, ctls_template_t const *template);


ctls_op_status_t ctls_extn_client_hello_to_wire(uint8_t *buffer, size_t *offset,
                                                ctls_hsmg_client_hello_t *
                                                client_hello,
                                                ctls_wire_format_t wire_format);

ctls_op_status_t ctls_extn_client_hello_to_struct(
    uint8_t *buffer, size_t *offset,
    ctls_hsmg_client_hello_t *client_hello,
    ctls_template_t const *template);

ctls_op_status_t ctls_extn_client_hello_create(
    ctls_hsmg_client_hello_t *client_hello,
    ctls_template_t const *template);
ctls_op_status_t ctls_extn_server_hello_to_wire(uint8_t *buffer, size_t *offset,
                                                ctls_hsmg_server_hello_t *
                                                server_hello,
                                                ctls_wire_format_t const
                                                wire_format);

ctls_op_status_t ctls_extn_server_hello_to_struct(void);

ctls_op_status_t ctls_extn_server_hello_create(
    ctls_hsmg_server_hello_t *server_hello,
    ctls_template_t const *template);

ctls_op_status_t ctls_extn_encrypted_extensions_to_wire(
    uint8_t *buffer, size_t *offset,
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions,
    ctls_wire_format_t const wire_format);

ctls_op_status_t ctls_extn_encrypted_extensions_to_struct(void);

ctls_op_status_t ctls_extn_encrypted_extensions_create(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions,
    ctls_template_t const *template);

ctls_op_status_t ctls_extn_client_hello_build(
    ctls_hsmg_client_hello_t *client_hello,
    ctls_template_t const *template,
    uint8_t *buffer, size_t *offset);

#endif
