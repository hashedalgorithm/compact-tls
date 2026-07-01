//
// Created by Sanjay Kumar Kumaravelan on 03/06/26.
//

#include <string.h>
#include "ctls/core.h"
#include "ctls/ctls.h"      /* pulls crypto.h, record.h, hsmg.h, psa/crypto.h */
#include "ctls/templates.h" /* full ctls_template_t struct definition */

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

ctls_status_t ctls_core_handshake_state_update(ctls_hshk_state_t const state) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    CTLS_CHECK_NULL_STRUCT(hshk_data);

    hshk_data->state = state;
    return CTLS_STATUS_SUCCESS;
}

/*
 * ClientHello.
 *
 *   CLIENT: called after CH is serialized and sent — hash it into the
 *           transcript. No validation needed on what we constructed.
 *   SERVER: called after CH is deserialized — TODO: validate extensions,
 *           check profile_id matches our template, etc.
 */
ctls_status_t ctls_core_client_hello_internal_op(ctls_record_t *record) {
    CTLS_CHECK_NULL_STRUCT(record);

#if CTLS_CLIENT
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_SERVER_HELLO);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_CLIENT_HELLO);
#elif CTLS_SERVER
    /* TODO: server-side ClientHello validation. */
    (void) record; return CTLS_STATUS_SUCCESS;
#else
    (void) record; return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}

/*
 * ServerHello.
 *
 *   CLIENT: called after SH is deserialized — validate protocol version and
 *           cipher suite against the active template, then hash SH.
 *   SERVER: called after SH is serialized and sent — TODO: hash SH.
 */
ctls_status_t ctls_core_server_hello_internal_op(ctls_record_t *record) {
#if CTLS_CLIENT
    ctls_hsmg_server_hello_t const *server_hello = &record->record_body.handshake.
            handshake_message_body.server_hello;
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(template);
    /* Verify the negotiated TLS version is 1.3 (RFC 8446 §4.1.3). */
    if (server_hello->protocol_version != CTLS_HSMG_PROTOCOL_VERSION_1_3) {
        ctls_alert_send(record,
                        CTLS_HSMG_ALERT_TYPE_PROTOCOL_VERSION,
                        CTLS_HSMG_ALERT_LEVEL_FATAL,
                        CTLS_ENTITY_CLIENT,
                        CTLS_PHASE_HANDSHAKE);
        return CTLS_STATUS_HSMG_INVALID_MSG_TYPE;
    }

    /*
     * If cipher_suite is present on the wire (non-zero sentinel), verify it
     * matches what the template pins. A mismatch indicates a misconfigured
     * peer or a downgrade attempt.
     */
    if (server_hello->cipher_suite != CTLS_HSMG_CIPHER_SUITE_SENTINEL && server_hello->
        cipher_suite != template->cipher_suite) {
        ctls_alert_send(record,
                        CTLS_HSMG_ALERT_TYPE_ILLEGAL_PARAMETER,
                        CTLS_HSMG_ALERT_LEVEL_FATAL,
                        CTLS_ENTITY_CLIENT,
                        CTLS_PHASE_HANDSHAKE);
        return CTLS_STATUS_HSMG_INVALID_MSG_TYPE;
    }

    ctls_core_handshake_state_update(CTLS_HSHK_STATE_KEY_SCHEDULED);

    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_SERVER_HELLO);

#elif CTLS_SERVER
    /* TODO: server-side: hash ServerHello after sending. */
    (void) record; return CTLS_STATUS_SUCCESS;
#else
    (void) record; return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}

/*
 * EncryptedExtensions — individual hook (not invoked in the combined-flight
 * model; EE is processed inside ctls_core_server_flight_op).
 */
ctls_status_t ctls_core_encrypted_extensions_internal_op(ctls_record_t *record) {
    (void) record;
#if CTLS_CLIENT
    return CTLS_STATUS_NOT_IMPLEMENTED;
#elif CTLS_SERVER
    return CTLS_STATUS_SUCCESS; /* TODO */
#else
    return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}

/*
 * CertificateRequest — individual hook (not invoked in current flow).
 */
ctls_status_t ctls_core_certificate_request_internal_op(ctls_record_t *record) {
    (void) record;
#if CTLS_CLIENT
    return CTLS_STATUS_NOT_IMPLEMENTED;
#elif CTLS_SERVER
    return CTLS_STATUS_SUCCESS; /* TODO */
#else
    return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}

/*
 * Certificate — individual hook (not invoked in current flow).
 */
ctls_status_t ctls_core_certificate_internal_op(ctls_record_t *record) {
    (void) record;
#if CTLS_CLIENT
    return CTLS_STATUS_NOT_IMPLEMENTED;
#elif CTLS_SERVER
    return CTLS_STATUS_SUCCESS; /* TODO */
#else
    return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}

/*
 * CertificateVerify — individual hook (not invoked in current flow).
 */
ctls_status_t ctls_core_certificate_verify_internal_op(ctls_record_t *record) {
    (void) record;
#if CTLS_CLIENT
    return CTLS_STATUS_NOT_IMPLEMENTED;
#elif CTLS_SERVER
    return CTLS_STATUS_SUCCESS; /* TODO */
#else
    return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}

/*
 * Finished — individual hook (not invoked in current flow).
 */
ctls_status_t ctls_core_finished_internal_op(ctls_record_t *record) {
    (void) record;
#if CTLS_CLIENT
    return CTLS_STATUS_NOT_IMPLEMENTED;
#elif CTLS_SERVER
    return CTLS_STATUS_SUCCESS; /* TODO */
#else
    return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}

/*
 * ServerFlight (EE + Certificate + CertificateVerify + Finished).
 *
 *   CLIENT: called after the AEAD-decrypted server flight is parsed.
 *     Sub-messages are hashed in order (each must be in the transcript before
 *     the next is verified):
 *
 *       Verify CertificateVerify  ← over Transcript-Hash(template||CH||SH)
 *       Verify Finished           ← over Transcript-Hash(template||CH||SH)
 *       Hash(EE)
 *       Hash(Certificate)
 *       Hash(CertificateVerify)
 *       Hash(Finished)
 *
 *     Alert sent and error returned on any verification failure.
 *   SERVER: not called in the server flow.
 */

ctls_status_t ctls_core_server_flight_op(ctls_record_t *record) {
#if CTLS_CLIENT
    ctls_crypto_t *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    ctls_template_t const *tmpl = ctls_template_get();

    ctls_hsmg_server_flight_t const *flight = &record->record_body.handshake.
            handshake_message_body.server_flight;

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_CERTIFICATE_VERIFY);
    if (result != CTLS_STATUS_SUCCESS) return result;

    uint16_t const cert_id = flight->certificate.certificate_entries[0].certificate_id;
    result = CTLS_STATUS_CRYPTO_CERT_PUB_KEY_IMPORT_FAILED;
    for (uint8_t i = 0; i < CTLS_COUNT_KNOWN_CERTIFICATES; i++) {
        if (tmpl->known_certificates.entries[i].certificate_id == cert_id) {
            result = ctls_certificate_public_key_import(tmpl->known_certificates.entries[
                                                            i].certificate,
                                                        tmpl->known_certificates.entries[
                                                            i].certificate_length,
                                                        &crypto->
                                                        peer_certificate_public_key);
            break;
        }
    }
    if (result != CTLS_STATUS_SUCCESS) {
        return ctls_alert_send(record,
                               CTLS_HSMG_ALERT_TYPE_UNKNOWN_CA,
                               CTLS_HSMG_ALERT_LEVEL_FATAL,
                               CTLS_ENTITY_CLIENT,
                               CTLS_PHASE_HANDSHAKE);
    }

    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_FINISHED);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_signed_bytes_verify(&crypto->peer_certificate_public_key,
                                      CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) {
        return ctls_alert_send(record,
                               CTLS_HSMG_ALERT_TYPE_DECRYPT_ERROR,
                               CTLS_HSMG_ALERT_LEVEL_FATAL,
                               CTLS_ENTITY_CLIENT,
                               CTLS_PHASE_HANDSHAKE);
    }

    uint8_t verify_data_expected[CTLS_SIZE_HASH];

    result = ctls_finished_key_generate(CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_verify_data_generate(CTLS_ENTITY_SERVER, verify_data_expected);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (memcmp(verify_data_expected, hshk_data->server_verify_data, CTLS_SIZE_HASH) !=
        0) {
        return ctls_alert_send(record,
                               CTLS_HSMG_ALERT_TYPE_DECRYPT_ERROR,
                               CTLS_HSMG_ALERT_LEVEL_FATAL,
                               CTLS_ENTITY_CLIENT,
                               CTLS_PHASE_HANDSHAKE);
    }

    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_SERVER_FLIGHT);

#elif CTLS_SERVER
    /* Server does not receive a server flight — this hook is unused. */
    return CTLS_STATUS_NOT_IMPLEMENTED;
#else
    (void) record; return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}

/*
 * ClientFlight (Certificate + CertificateVerify + Finished).
 *
 *   CLIENT: called after the client flight is serialized and sent — hash it.
 *   SERVER: called after the client flight is decrypted and parsed —
 *           TODO: verify CertificateVerify and Finished.
 */
ctls_status_t ctls_core_client_flight_op(ctls_record_t *record) {
#if CTLS_CLIENT
    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_CLIENT_FLIGHT);
#elif CTLS_SERVER
    /* TODO: server-side client flight verification (mirror of server_flight_op). */
    (void) record; return CTLS_STATUS_SUCCESS;
#else
    (void) record; return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}


