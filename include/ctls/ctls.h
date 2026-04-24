//
// Created by Sanjay Kumar Kumaravelan on 31/03/26.
//


#ifndef CTLS__H
#define CTLS__H

#include <stdint.h>
#include "crypto.h"
#include "record.h"

ctls_op_status_t ctls_context_init(ctls_context_t *context,
                                   const ctls_transport_t *transport);
ctls_op_status_t ctls_connect(ctls_context_t *context);
ctls_op_status_t ctls_read(ctls_context_t const *context, uint8_t *buffer,
                           size_t buffer_length);
ctls_op_status_t ctls_write(ctls_context_t const *context, uint8_t *buffer,
                            size_t buffer_length);


#endif
