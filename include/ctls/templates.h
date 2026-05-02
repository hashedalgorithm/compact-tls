//
// Created by Sanjay Kumar Kumaravelan on 31/03/26.
//


#ifndef CTLS_TEMPLATES_H
#define CTLS_TEMPLATES_H

#include "config.h"
#include "extensions.h"

#define CTLS_IS_TEMPLATE_BYTES_INITIALIZED(buffer, length)          \
    ((buffer) != NULL && length != 0)


struct ctls_template_bytes {
    uint8_t *data;
    ctls_size_t length;
};
struct ctls_tmpl_dhe_group {
    ctls_size_t key_share_length;
    ctls_extn_dhe_group_type_t dhe_group;
};
struct ctls_tmpl_signature_algorithm {
    ctls_size_t signature_length;
    ctls_extn_signature_algorithm_type_t signature_algorithm_type;
};
struct ctls_tmpl_predefined_extensions {
    ctls_template_bytes_t server_name;
    ctls_max_fragment_length_t maximum_fragment_length;
    ctls_template_bytes_t certificate_status_request;
    ctls_extn_heartbeat_mode_t heartbeat_mode;
    ctls_template_bytes_t alpn;
    ctls_extn_certificate_type_t client_certificate_type;
    ctls_extn_certificate_type_t server_certificate_type;
    ctls_extn_psk_key_exchange_mode_t psk_key_exchange_modes;
    ctls_extn_post_handshake_auth_t post_handshake_auth;
    ctls_extn_signature_algorithm_type_t signature_algorithm_cert;
};
struct ctls_tmpl_extension {
    ctls_tmpl_predefined_extensions_t predefined_extensions;
    ctls_tmpl_expected_extensions_t expected_extensions;
    ctls_tmpl_self_delimiting_extensions_t self_delimiting_aextensions;
    uint16_t allow_additional;
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
    ctls_tmpl_extension_t client_hello_extension;
    ctls_tmpl_extension_t server_hello_extension;
    ctls_tmpl_extension_t encrypted_extension;
    ctls_tmpl_extension_t certificate_request_extension;
    uint8_t finished_size;
};


#if CTLS_CLIENT

extern const ctls_template_t ctls_template_1;

ctls_op_status_t ctls_template_set(uint8_t profile_id, ctls_context_t *context);
ctls_op_status_t ctls_template_element_to_wire(uint8_t *buffer,
                                               ctls_size_t *offset,
                                               ctls_template_t const *template,
                                               ctls_tmpl_type_t type);
ctls_op_status_t ctls_tmpl_extension_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_tmpl_extension_t const *extensions);
ctls_op_status_t ctls_template_to_wire(uint8_t *buffer, ctls_template_t const *template);


#endif


#if CTLS_SERVER
// TODO
// Define default profiles for server
#endif

#endif
