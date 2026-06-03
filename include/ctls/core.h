//
// Created by Sanjay Kumar Kumaravelan on 03/06/26.
//

#ifndef CTLS_CORE_H
#define CTLS_CORE_H

#include "config.h"
#include "ctls.h"
#include "types.h"

ctls_status_t ctls_core_client_hello_internal_op(ctls_record_t *record);
ctls_status_t ctls_core_server_hello_internal_op(ctls_record_t *record);
ctls_status_t ctls_core_encrypted_extensions_internal_op(ctls_record_t *record);
ctls_status_t ctls_core_certificate_request_internal_op(ctls_record_t *record);
ctls_status_t ctls_core_certificate_internal_op(ctls_record_t *record);
ctls_status_t ctls_core_certificate_verify_internal_op(ctls_record_t *record);
ctls_status_t ctls_core_finished_internal_op(ctls_record_t *record);


#endif //CTLS_CORE_H

