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
 *   SERVER: called after CH is deserialized — checks profile_id against the
 *           active template (RFC 8446 illegal_parameter on mismatch), then
 *           hashes CH. Extension-level validation is still open.
 */
ctls_status_t ctls_core_client_hello_internal_op(ctls_record_t *record) {
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
#if CTLS_CLIENT

    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_SERVER_HELLO);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_CLIENT_HELLO);
#elif CTLS_SERVER
    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_START);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_template_t const *template = ctls_template_get();
    CTLS_CHECK_NULL_STRUCT(template);

    /* profile_id selects the template both peers pre-negotiated (cTLS has
     * no on-wire cipher/extension negotiation) — a mismatch means the
     * client is running a different profile than we are. */
    if (record->profile_id != template->profile_id) {
        return CTLS_STATUS_ALERT_ILLEGAL_PARAMETER;
    }
    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_SERVER_HELLO);
    if (result != CTLS_STATUS_SUCCESS) return result;
    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_CLIENT_HELLO);
#else
    return CTLS_STATUS_INVALID_INVOCATION;
#endif
}

/*
 * ServerHello.
 *
 *   CLIENT: called after SH is deserialized — validate protocol version and
 *           cipher suite against the active template, then hash SH.
 *   SERVER: called after SH is serialized and sent — hash SH.
 */
ctls_status_t ctls_core_server_hello_internal_op(ctls_record_t *record) {
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

#if CTLS_CLIENT
    ctls_hsmg_server_hello_t const *server_hello =
            &record->record_body.handshake.handshake_message_body.server_hello;
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(template);
    CTLS_CHECK_NULL_STRUCT(record);
    /* Verify the negotiated TLS version is 1.3 (RFC 8446 §4.1.3). */
    if (server_hello->protocol_version != CTLS_HSMG_PROTOCOL_VERSION_1_3)
        return CTLS_STATUS_ALERT_PROTOCOL_VERSION;


    /*
     * If cipher_suite is present on the wire (non-zero sentinel), verify it
     * matches what the template pins. A mismatch indicates a misconfigured
     * peer or a downgrade attempt.
     */
    if (server_hello->cipher_suite != CTLS_HSMG_CIPHER_SUITE_SENTINEL &&
        server_hello->cipher_suite != template->cipher_suite)
        return CTLS_STATUS_ALERT_ILLEGAL_PARAMETER;

    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_KEY_SCHEDULED);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_SERVER_HELLO);

#elif CTLS_SERVER
    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_KEY_SCHEDULED);
    if (result != CTLS_STATUS_SUCCESS) return result;
    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_SERVER_HELLO);
#else
    return CTLS_STATUS_INVALID_INVOCATION;
#endif
}

/*
 * EncryptedExtensions — individual hook (not invoked in the combined-flight
 * model; EE is processed inside ctls_core_server_flight_op).
 */
ctls_status_t ctls_core_encrypted_extensions_internal_op(ctls_record_t *record) {
    CTLS_CHECK_NULL(record);

#if CTLS_CLIENT
    return CTLS_STATUS_SUCCESS;
#elif CTLS_SERVER
    return CTLS_STATUS_SUCCESS;
#else
    return CTLS_STATUS_INVALID_INVOCATION;
#endif
}

/*
 * CertificateRequest — individual hook (not invoked in current flow).
 */
ctls_status_t ctls_core_certificate_request_internal_op(ctls_record_t *record) {
    CTLS_CHECK_NULL(record);

#if CTLS_CLIENT
    return CTLS_STATUS_SUCCESS;
#elif CTLS_SERVER
    return CTLS_STATUS_SUCCESS;
#else
    return CTLS_STATUS_INVALID_INVOCATION;
#endif
}

/*
 * Certificate — individual hook (not invoked in current flow).
 */
ctls_status_t
ctls_core_certificate_internal_op(ctls_hsmg_certificate_t const *certificate) {
    ctls_crypto_t *crypto = ctls_crypto_get();
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(template);
    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL_STRUCT(certificate);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    uint16_t const cert_id = certificate->certificate_entries[0].certificate_id;
    result = CTLS_STATUS_CRYPTO_CERT_PUB_KEY_IMPORT_FAILED;

    for (uint8_t i = 0; i < CTLS_COUNT_KNOWN_CERTIFICATES; i++) {
        if (template->known_certificates.entries[i].certificate_id == cert_id) {
            result = ctls_certificate_public_key_import(
                    template->known_certificates.entries[i].certificate,
                    template->known_certificates.entries[i].certificate_length,
                    &crypto->peer_certificate_public_key);
            break;
        }
    }
    if (result != CTLS_STATUS_SUCCESS) return CTLS_STATUS_ALERT_UNKNOWN_CA;

    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_FINISHED);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return result;
}

/*
 * CertificateVerify — individual hook (not invoked in current flow).
 */
ctls_status_t ctls_core_certificate_verify_internal_op() {
    ctls_crypto_t const *crypto = ctls_crypto_get();
    CTLS_CHECK_NULL_STRUCT(crypto);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_signed_bytes_verify(&crypto->peer_certificate_public_key,
                                      CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) return CTLS_STATUS_ALERT_DECRYPT_ERROR;

    return result;
}

/*
 * Finished — individual hook (not invoked in current flow).
 */
ctls_status_t ctls_core_finished_internal_op() {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hshk_data);

    uint8_t verify_data_expected[CTLS_SIZE_HASH];
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_finished_key_generate(CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_verify_data_generate(CTLS_ENTITY_SERVER, verify_data_expected);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (memcmp(verify_data_expected, hshk_data->server_verify_data, CTLS_SIZE_HASH) !=
        0) {
        return CTLS_STATUS_ALERT_DECODE_ERROR;
    }

    return result;
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

ctls_status_t ctls_core_server_flight_op(ctls_record_t const *record) {
    ctls_status_t result = CTLS_STATUS_SUCCESS;
#if CTLS_CLIENT
    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_CERTIFICATE_VERIFY);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_core_certificate_internal_op(
            &record->record_body.handshake.handshake_message_body.server_flight
                     .certificate);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_FINISHED);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_core_certificate_verify_internal_op();
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_core_finished_internal_op();
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_SERVER_FLIGHT);

#elif CTLS_SERVER
    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_SERVER_FLIGHT);
#else
    return CTLS_STATUS_INVALID_INVOCATION;
#endif
}

/*
 * ClientFlight (Certificate + CertificateVerify + Finished).
 *
 *   CLIENT: called after the client flight is serialized and sent — hash it.
 *   SERVER: called after the client flight is decrypted and parsed — imports
 *           the peer certificate, verifies CertificateVerify and Finished
 *           (same sequence as ctls_core_server_flight_op's CLIENT branch),
 *           then hashes the flight.
 */
ctls_status_t ctls_core_client_flight_op(ctls_record_t const *record) {
#if CTLS_CLIENT
    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_CLIENT_FLIGHT);
#elif CTLS_SERVER
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_CERTIFICATE_VERIFY);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_core_certificate_internal_op(
            &record->record_body.handshake.handshake_message_body.client_flight
                     .certificate);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_FINISHED);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_core_certificate_verify_internal_op();
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_core_finished_internal_op();
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_transcript_hash_update(record, CTLS_HSMG_TYPE_CLIENT_FLIGHT);
#else
    return CTLS_STATUS_INVALID_INVOCATION;
#endif
}
