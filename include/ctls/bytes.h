//
// Created by Sanjay Kumar Kumaravelan on 05/04/26.
//

#ifndef CTLS_BYTES_H
#define CTLS_BYTES_H

#include <stdint.h>
#include "types.h"


// write primitives — big-endian, network byte order
static inline void ctls_write_u8(uint8_t *buffer,
                                 ctls_size_t *offset,
                                 uint8_t const value) {
    buffer[(*offset)++] = value;
}

static inline void ctls_write_u16(uint8_t *buffer,
                                  ctls_size_t *offset,
                                  uint16_t const value) {
    buffer[(*offset)++] = (value >> 8) & 0xFF;
    buffer[(*offset)++] = value & 0xFF;
}

static inline void ctls_write_u24(uint8_t *buffer,
                                  ctls_size_t *offset,
                                  uint16_t const value) {
    buffer[(*offset)++] = (value >> 16) & 0xFF;
    buffer[(*offset)++] = (value >> 8) & 0xFF;
    buffer[(*offset)] = value & 0xFF;
}

static inline void ctls_write_u32(uint8_t *buffer,
                                  ctls_size_t *offset,
                                  uint32_t const value) {
    for (int i = 3; i >= 0; i--) {
        buffer[(*offset)++] = (value >> (i * 8)) & 0xFF;
    }
}


static inline void ctls_write_u64(uint8_t *buffer,
                                  ctls_size_t *offset,
                                  uint64_t const value) {
    for (int i = 7; i >= 0; i--) {
        buffer[(*offset)++] = (value >> (i * 8)) & 0xFF;
    }
}

static inline void ctls_write_bytes(uint8_t *destination_buffer,
                                    ctls_size_t *destination_offset,
                                    ctls_size_t write_size,
                                    uint8_t const *source_buffer) {
    memcpy(destination_buffer + *destination_offset, source_buffer, write_size);
    *destination_offset += write_size;
}

// read primitives — big-endian, network byte order
static inline uint8_t ctls_read_u8(uint8_t const *buffer, ctls_size_t *offset) {
    return buffer[(*offset)++];
}

static inline uint16_t ctls_read_u16(uint8_t const *buffer, ctls_size_t *offset) {
    const uint16_t value = (uint16_t) ((buffer[*offset] << 8) | buffer[*offset + 1]);
    *offset += 2;
    return value;
}

static inline uint64_t ctls_read_u64(uint8_t const *buffer, ctls_size_t *offset) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | buffer[(*offset)++];
    }
    return value;
}

static inline void ctls_read_bytes(uint8_t *destination_buffer,
                                   ctls_size_t write_size,
                                   uint8_t const *source_buffer,
                                   ctls_size_t *source_buffer_offset) {
    memcpy(destination_buffer, source_buffer + *source_buffer_offset, write_size);
    *source_buffer_offset += write_size;
}

static inline uint8_t ctls_epoch_compress(uint64_t const *full_epoch) {
    return (uint8_t) (*full_epoch & 0x03);
}

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
