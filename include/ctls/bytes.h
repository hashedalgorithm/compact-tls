//
//
// Created by Sanjay Kumar Kumaravelan on 05/04/26.

/**
 * @file bytes.h
 * @brief Wire encoding primitives + epoch helpers.
 *
 * TLS presentation language (RFC 8446, Section 3) encodes all multi-byte
 * numbers in network byte order: "multibyte numeric quantities" are big-endian,
 * vectors are length-prefixed. Every serializer in this library goes through
 * these helpers, so the byte order is fixed in exactly one place.
 *
 * Convention: each write/read advances *offset past the bytes it consumed.
 *
 * Bounds checking: every ctls_write_* / ctls_read_* takes an explicit `limit`
 * — the capacity of the buffer being written to (write) or read from
 * (read), NOT always CTLS_SIZE_WIRE_BUFFER. Pass CTLS_SIZE_WIRE_BUFFER for
 * wire-buffer operations; pass the real size (e.g. sizeof(local_array)) for
 * smaller scratch buffers such as crypto.c's HKDF label/context builders.
 * The check is against the buffer's allocated capacity (offset + size <=
 * limit), not the number of bytes actually received on the wire — that's a
 * separate message-level validation concern, not a memory-safety one. Each
 * function returns CTLS_STATUS_BOUNDS_EXCEEDED and reads/writes nothing if
 * the operation would exceed limit; callers must check the return value
 * like any other ctls_status_t-returning call. Reads write their result
 * through an output pointer instead of returning it directly, since the
 * return value is now the status.
 */

#ifndef CTLS_BYTES_H
#define CTLS_BYTES_H

#include <stdint.h>
#include <string.h>
#include "types.h"

/** Return CTLS_STATUS_BOUNDS_EXCEEDED if writing `size` bytes at `offset` would exceed `limit`. */
static inline ctls_status_t ctls_bounds_check(ctls_size_t const offset,
                                              ctls_size_t const size,
                                              ctls_size_t const limit) {
    if (offset + size > limit) return CTLS_STATUS_BOUNDS_EXCEEDED;
    return CTLS_STATUS_SUCCESS;
}

// write primitives — big-endian, network byte order
static inline ctls_status_t ctls_write_u8(uint8_t *buffer,
                                          ctls_size_t *offset,
                                          uint8_t const value,
                                          ctls_size_t const limit) {
    ctls_status_t const result = ctls_bounds_check(*offset, 1U, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    buffer[(*offset)++] = value;
    return CTLS_STATUS_SUCCESS;
}

static inline ctls_status_t ctls_write_u16(uint8_t *buffer,
                                           ctls_size_t *offset,
                                           uint16_t const value,
                                           ctls_size_t const limit) {
    ctls_status_t const result = ctls_bounds_check(*offset, 2U, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    buffer[(*offset)++] = (value >> 8) & 0xFF;
    buffer[(*offset)++] = value & 0xFF;
    return CTLS_STATUS_SUCCESS;
}

/* u24: TLS uses 3-byte lengths e.g. for Handshake.length (RFC 8446 §4). */
static inline ctls_status_t ctls_write_u24(uint8_t *buffer,
                                           ctls_size_t *offset,
                                           uint32_t const value,
                                           ctls_size_t const limit) {
    ctls_status_t const result = ctls_bounds_check(*offset, 3U, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    buffer[(*offset)++] = (value >> 16) & 0xFF;
    buffer[(*offset)++] = (value >> 8) & 0xFF;
    buffer[(*offset)++] = value & 0xFF;
    return CTLS_STATUS_SUCCESS;
}

static inline ctls_status_t ctls_write_u32(uint8_t *buffer,
                                           ctls_size_t *offset,

                                           uint32_t const value,
                                           ctls_size_t const limit) {
    ctls_status_t const result = ctls_bounds_check(*offset, 4U, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    for (int i = 3; i >= 0; i--) {
        buffer[(*offset)++] = (value >> (i * 8)) & 0xFF;
    }
    return CTLS_STATUS_SUCCESS;
}


static inline ctls_status_t ctls_write_u64(uint8_t *buffer,
                                           ctls_size_t *offset,
                                           uint64_t const value,
                                           ctls_size_t const limit) {
    ctls_status_t const result = ctls_bounds_check(*offset, 8U, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    for (int i = 7; i >= 0; i--) {
        buffer[(*offset)++] = (value >> (i * 8)) & 0xFF;
    }
    return CTLS_STATUS_SUCCESS;
}

static inline ctls_status_t ctls_write_bytes(uint8_t *destination_buffer,
                                             ctls_size_t *destination_offset,
                                             ctls_size_t write_size,
                                             uint8_t const *source_buffer,
                                             ctls_size_t const limit) {
    ctls_status_t const result = ctls_bounds_check(*destination_offset, write_size, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    memcpy(destination_buffer + *destination_offset, source_buffer, write_size);
    *destination_offset += write_size;
    return CTLS_STATUS_SUCCESS;
}

/* Same as ctls_write_bytes; takes char* so string literals need no cast. */
static inline ctls_status_t ctls_write_char_bytes(uint8_t *destination_buffer,
                                                  ctls_size_t *destination_offset,
                                                  ctls_size_t write_size,
                                                  char const *source_buffer,
                                                  ctls_size_t const limit) {
    ctls_status_t const result = ctls_bounds_check(*destination_offset, write_size, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    memcpy(destination_buffer + *destination_offset, source_buffer, write_size);
    *destination_offset += write_size;
    return CTLS_STATUS_SUCCESS;
}

// read primitives — big-endian, network byte order
static inline ctls_status_t ctls_read_u8(uint8_t const *buffer,
                                         ctls_size_t *offset,
                                         ctls_size_t const limit,
                                         uint8_t *value) {
    ctls_status_t const result = ctls_bounds_check(*offset, 1U, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    *value = buffer[(*offset)++];
    return CTLS_STATUS_SUCCESS;
}

static inline ctls_status_t ctls_read_u16(uint8_t const *buffer,
                                          ctls_size_t *offset,
                                          ctls_size_t const limit,
                                          uint16_t *value) {
    ctls_status_t const result = ctls_bounds_check(*offset, 2U, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    *value = (uint16_t) ((buffer[*offset] << 8) | buffer[*offset + 1]);
    *offset += 2;
    return CTLS_STATUS_SUCCESS;
}

static inline ctls_status_t ctls_read_u24(uint8_t const *buffer,
                                          ctls_size_t *offset,
                                          ctls_size_t const limit,
                                          uint32_t *value) {
    ctls_status_t const result = ctls_bounds_check(*offset, 3U, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    *value = ((uint32_t) buffer[*offset] << 16) | ((uint32_t) buffer[*offset + 1] << 8) |
             (uint32_t) buffer[*offset + 2];
    *offset += 3;
    return CTLS_STATUS_SUCCESS;
}

static inline ctls_status_t ctls_read_u32(uint8_t const *buffer,
                                          ctls_size_t *offset,
                                          ctls_size_t const limit,
                                          uint32_t *value) {
    ctls_status_t const result = ctls_bounds_check(*offset, 4U, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    *value = ((uint32_t) buffer[*offset] << 24) | ((uint32_t) buffer[*offset + 1] << 16) |
             ((uint32_t) buffer[*offset + 2] << 8) | (uint32_t) buffer[*offset + 3];
    *offset += 4;
    return CTLS_STATUS_SUCCESS;
}

static inline ctls_status_t ctls_read_u64(uint8_t const *buffer,
                                          ctls_size_t *offset,
                                          ctls_size_t const limit,
                                          uint64_t *value) {
    ctls_status_t const result = ctls_bounds_check(*offset, 8U, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | buffer[(*offset)++];
    }
    *value = v;
    return CTLS_STATUS_SUCCESS;
}

static inline ctls_status_t ctls_read_bytes(uint8_t *destination_buffer,
                                            ctls_size_t write_size,
                                            uint8_t const *source_buffer,
                                            ctls_size_t *source_buffer_offset,
                                            ctls_size_t const limit) {
    ctls_status_t const result =
            ctls_bounds_check(*source_buffer_offset, write_size, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;
    memcpy(destination_buffer, source_buffer + *source_buffer_offset, write_size);
    *source_buffer_offset += write_size;
    return CTLS_STATUS_SUCCESS;
}

/*
 * Epoch compression — DTLS 1.3 style (RFC 9147, Section 4): the unified
 * header carries only "the low-order two bits of the epoch" in its config
 * octet; both sides track the full 64-bit epoch and reconstruct it from
 * those two bits. cTLS reuses the same scheme in its unified header.
 */
static inline uint8_t ctls_epoch_compress(uint64_t const *full_epoch) {
    return (uint8_t) (*full_epoch & 0x03);
}

/*
 * Reconstruct the full epoch from received 2-bit ee_bits. Epochs only move
 * forward: take the current epoch with its low 2 bits replaced; if that went
 * backwards, the 2-bit counter wrapped, so advance one full cycle (+4).
 */
static inline void ctls_epoch_expand(uint8_t ee_bits, uint64_t *current_epoch) {
    /* Mask to 2 bits — caller may pass raw config octet */
    ee_bits &= 0x03;

    /* Base candidate: replace low 2 bits of current epoch with ee_bits */
    uint64_t candidate = (*current_epoch & ~(uint64_t) 0x03) | ee_bits;

    if (candidate < *current_epoch) {
        /* ee_bits wrapped — epoch has advanced one full cycle */
        candidate += 4;
    }

    *current_epoch = candidate;
}
#endif //CTLS_BYTES_H
