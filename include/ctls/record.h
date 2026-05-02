//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#ifndef CTLS_RECORD_H
#define CTLS_RECORD_H

#include "hsmg.h"

struct ctls_recd_config_octet {
    uint8_t c_bit; // connection_id
    uint8_t s_bit; // sequence_number
    uint8_t l_bit; // length
    uint8_t epoch;
};
struct ctls_record {
    /* For Client Hello and Server Hello */
    uint8_t content_type;
    uint8_t profile_id;
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

ctls_op_status_t ctls_build_unified_header(const ctls_recd_config_octet_t *config,
                                           uint16_t sequence_number,
                                           uint16_t length,
                                           uint8_t *buffer,
                                           ctls_size_t *buffer_length);

ctls_op_status_t ctls_write_body_length(uint8_t *buffer,
                                        ctls_size_t *offset,
                                        ctls_size_t body_length);

ctls_op_status_t ctls_record_serialize(ctls_template_t const *template,
                                       ctls_record_t const *record,
                                       uint8_t *buffer,
                                       ctls_size_t buffer_size,
                                       ctls_size_t *buffer_length);
ctls_op_status_t ctls_record_deserialize(ctls_template_t const *template,
                                         ctls_record_t const *record,
                                         uint8_t *buffer,
                                         ctls_size_t buffer_length);

ctls_op_status_t ctls_recd_client_hello_create(ctls_record_t *record,
                                               ctls_hshk_buffer_t *hshk_buffer,
                                               ctls_template_t const *template);
ctls_op_status_t ctls_recd_client_hello_to_struct(void);
ctls_op_status_t ctls_recd_client_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_size_t buffer_size,
                                                ctls_record_t const *record,
                                                ctls_template_t const *template,
                                                ctls_wire_format_t wire_format);

ctls_op_status_t ctls_recd_server_hello_create(void);
ctls_op_status_t ctls_recd_server_hello_to_struct(void);
ctls_op_status_t ctls_recd_server_hello_to_wire(void);

ctls_op_status_t ctls_recd_encrypted_extensions_create(void);
ctls_op_status_t ctls_recd_encrypted_extensions_to_struct(void);
ctls_op_status_t ctls_recd_encrypted_extensions_to_wire(void);

ctls_op_status_t ctls_recd_certificate_create(void);
ctls_op_status_t ctls_recd_certificate_to_struct(void);
ctls_op_status_t ctls_recd_certificate_to_wire(void);

ctls_op_status_t ctls_recd_certificate_verify_create(void);
ctls_op_status_t ctls_recd_certificate_verify_to_struct(void);
ctls_op_status_t ctls_recd_certificate_verify_to_wire(void);

ctls_op_status_t ctls_recd_finished_create(void);
ctls_op_status_t ctls_recd_finished_to_struct(void);
ctls_op_status_t ctls_recd_finished_to_wire(void);

#endif
