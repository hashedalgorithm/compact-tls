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

struct ctls_unified_header {
    /* Except for Client Hello and Server Hello */
    ctls_recd_config_octet_t config_octet;
    // To implement later when there is a scenario where UDP source address change
    // uint8_t connection_id;
    uint16_t sequence_number;
    uint16_t length;
    /* Except for Client Hello and Server Hello */
    uint64_t epoch;
};

struct ctls_record {
    uint8_t content_type; // Used only in CH, SH
    uint8_t profile_id; // Used only in CH, SH
    ctls_record_type_t type; // For internal reference
    ctls_unified_header_t unified_header;
    ctls_handshake_message_t record_body;
};


ctls_status_t ctls_unified_header_build(ctls_unified_header_t *unified_header,
                                        uint16_t sequence_number,
                                        uint16_t length,
                                        uint64_t const *epoch);
ctls_status_t ctls_unified_header_serialize(ctls_unified_header_t const *unified_header,
                                            uint8_t *buffer,
                                            ctls_size_t *offset);
ctls_status_t ctls_unified_header_deserialize(ctls_unified_header_t *unified_header,
                                              uint8_t const *buffer,
                                              ctls_size_t *offset);

ctls_status_t ctls_record_serialize(ctls_record_t const *record,
                                    uint8_t *buffer,
                                    ctls_size_t *offset);
ctls_status_t ctls_record_deserialize(ctls_record_t *record,
                                      ctls_hsmg_type_t hsmg_type,
                                      uint8_t const *buffer);

ctls_status_t ctls_recd_client_hello_create(ctls_record_t *record);
ctls_status_t ctls_recd_client_hello_to_struct();
ctls_status_t ctls_recd_client_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_record_t const *record,
                                             ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_server_hello_create(void);
ctls_status_t ctls_recd_server_hello_to_struct(ctls_record_t *record,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset);
ctls_status_t ctls_recd_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_record_t const *record,
                                             ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_encrypted_extensions_create(void);
ctls_status_t ctls_recd_encrypted_extensions_to_struct(ctls_record_t *record,
                                                       uint8_t const *buffer);
ctls_status_t ctls_recd_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_record_t const *record,
                                                     ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_certificate_request_create(void);
ctls_status_t ctls_recd_certificate_request_to_struct(ctls_record_t *record,
                                                      uint8_t const *buffer);
ctls_status_t ctls_recd_certificate_request_to_wire(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_record_t const *record,
                                                    ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_certificate_create(void);
ctls_status_t ctls_recd_certificate_to_struct(ctls_record_t *record,
                                              uint8_t const *buffer);
ctls_status_t ctls_recd_certificate_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_record_t const *record,
                                            ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_certificate_verify_create(ctls_record_t *record);
ctls_status_t ctls_recd_certificate_verify_to_struct(ctls_record_t *record,
                                                     uint8_t const *buffer);
ctls_status_t ctls_recd_certificate_verify_to_wire(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   ctls_record_t const *record,
                                                   ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_finished_create(void);
ctls_status_t ctls_recd_finished_to_struct(void);
ctls_status_t ctls_recd_finished_to_wire(void);

#endif
