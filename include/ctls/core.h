//
// Created by Sanjay Kumar Kumaravelan on 03/06/26.
//

/**
 * @file core.h
 * @brief Post-receive hook layer for each handshake message.
 *
 * The handshake driver in ctls.c deserializes each incoming record, then
 * calls the matching ctls_core_*_internal_op hook before advancing state.
 * These hooks are the extension point for application-level validation and
 * side effects (e.g. certificate chain verification, session ticket
 * processing) that sit above the crypto and record layers but below the
 * public ctls_connect API.
 *
 * All hooks follow the same contract:
 *   - record is the freshly deserialized record (read-only for validation,
 *     writable if the hook needs to annotate it).
 *   - Return CTLS_STATUS_SUCCESS to allow the handshake to continue.
 *   - Return any error to abort; the driver propagates it and sets
 *     CTLS_HSHK_STATE_ERROR.
 *
 * Currently all stubs return CTLS_STATUS_NOT_IMPLEMENTED.
 */

#ifndef CTLS_CORE_H
#define CTLS_CORE_H

#include "types.h"

/** Hook called after ClientHello is deserialized (server side). */
ctls_status_t ctls_core_client_hello_internal_op(ctls_record_t *record);
/** Hook called after ServerHello is deserialized and accepted. */
ctls_status_t ctls_core_server_hello_internal_op(ctls_record_t *record);
/** Hook called after EncryptedExtensions is deserialized. */
ctls_status_t ctls_core_encrypted_extensions_internal_op(ctls_record_t *record);
/** Hook called after CertificateRequest is deserialized. */
ctls_status_t ctls_core_certificate_request_internal_op(ctls_record_t *record);
/** Hook called after Certificate is deserialized (chain validation goes here). */
ctls_status_t ctls_core_certificate_internal_op(ctls_record_t *record);
/** Hook called after CertificateVerify is deserialized and signature checked. */
ctls_status_t ctls_core_certificate_verify_internal_op(ctls_record_t *record);
/** Hook called after Finished is deserialized and verify_data is authenticated. */
ctls_status_t ctls_core_finished_internal_op(ctls_record_t *record);
/** Hook called after the client flight (Certificate+CertVerify+Finished) is sent. */
ctls_status_t ctls_core_client_flight_op(ctls_record_t *record);
/** Hook called after the server flight (EE+Certificate+CertVerify+Finished) is received. */
ctls_status_t ctls_core_server_flight_op(ctls_record_t *record);

#endif //CTLS_CORE_H

