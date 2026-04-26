//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#ifndef CTLS_HSMG_H
#define CTLS_HSMG_H

#include "extensions.h"


struct ctls_hsmg_client_hello {
    ctls_hsmg_protocol_version_t protocol_version;
    ctls_hshk_buffer_block_t random;
    uint8_t legacy_session_id;
    ctls_hsmg_cipher_suite_type_t cipher_suite;
    uint8_t legacy_compression_methods;
    ctls_extn_client_hello_t extensions;
};

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
    ctls_size_t payload_length;
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


ctls_op_status_t ctls_hsmg_client_hello_create(ctls_handshake_message_t *hsmg,
                                               ctls_hshk_buffer_t *hshk_buffer,
                                               ctls_template_t const *template);
ctls_op_status_t ctls_hsmg_client_hello_to_struct(void);
ctls_op_status_t ctls_hsmg_client_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_size_t const *buffer_size,
                                                ctls_handshake_message_t const *hsmg,
                                                ctls_template_t const *template,
                                                ctls_wire_format_t wire_format);

ctls_op_status_t ctls_hsmg_server_hello_create(void);
ctls_op_status_t ctls_hsmg_server_hello_to_struct(void);
ctls_op_status_t ctls_hsmg_server_hello_to_wire(void);

ctls_op_status_t ctls_hsmg_encrypted_extensions_create(void);
ctls_op_status_t ctls_hsmg_encrypted_extensions_to_struct(void);
ctls_op_status_t ctls_hsmg_encrypted_extensions_to_wire(void);

ctls_op_status_t ctls_hsmg_certificate_create(void);
ctls_op_status_t ctls_hsmg_certificate_to_struct(void);
ctls_op_status_t ctls_hsmg_certificate_to_wire(void);

ctls_op_status_t ctls_hsmg_certificate_verify_create(void);
ctls_op_status_t ctls_hsmg_certificate_verify_to_struct(void);
ctls_op_status_t ctls_hsmg_certificate_verify_to_wire(void);

ctls_op_status_t ctls_hsmg_finished_create(void);
ctls_op_status_t ctls_hsmg_finished_to_struct(void);
ctls_op_status_t ctls_hsmg_finished_to_wire(void);


#endif
