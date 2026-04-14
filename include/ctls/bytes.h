//
// Created by Sanjay Kumar Kumaravelan on 05/04/26.
//

#ifndef CTLS_BYTES_H
#define CTLS_BYTES_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// write primitives — big-endian, network byte order
static inline void
ctls_write_u8(uint8_t *buffer, size_t *offset, uint8_t const value) {
    buffer[(*offset)++] = value;
}

static inline void ctls_write_u16(uint8_t *buffer, size_t *offset,
                                  uint16_t const value) {
    buffer[(*offset)++] = (value >> 8) & 0xFF;
    buffer[(*offset)++] = value & 0xFF;
}

static inline void ctls_write_u24(uint8_t *buffer, size_t *offset,
                                  uint16_t const value) {
    buffer[(*offset)++] = (value >> 16) & 0xFF;
    buffer[(*offset)++] = (value >> 8) & 0xFF;
    buffer[(*offset)] = value & 0xFF;
}

static inline void ctls_write_to_offset_u16(uint8_t *buffer, size_t *offset,
                                            uint16_t const value) {
    buffer[(*offset)] = (value >> 8) & 0xFF;
    buffer[(*offset)++] = value & 0xFF;
}


static inline void ctls_write_u64(uint8_t *buffer, size_t *offset,
                                  uint64_t const value) {
    for (int i = 7; i >= 0; i--) {
        buffer[(*offset)++] = (value >> (i * 8)) & 0xFF;
    }
}

static inline void ctls_write_bytes(uint8_t *destination_buffer, size_t length,
                                    const uint8_t *source_buffer,
                                    size_t *source_buffer_offset
) {
    memcpy(destination_buffer + *source_buffer_offset, source_buffer, length);
    *source_buffer_offset += length;
}

// read primitives — big-endian, network byte order
static inline uint8_t ctls_read_u8(const uint8_t *buffer, size_t *offset) {
    return buffer[(*offset)++];
}

static inline uint16_t ctls_read_u16(const uint8_t *buffer, size_t *offset) {
    const uint16_t value = (uint16_t) (
        (buffer[*offset] << 8) | buffer[*offset + 1]);
    *offset += 2;
    return value;
}

static inline uint64_t ctls_read_u64(const uint8_t *buffer, size_t *offset) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | buffer[(*offset)++];
    }
    return value;
}

static inline void ctls_read_bytes(uint8_t *destination_buffer, size_t length,
                                   const uint8_t *source_buffer,
                                   size_t *source_buffer_offset) {
    memcpy(destination_buffer, source_buffer + *source_buffer_offset, length);
    *source_buffer_offset += length;
}

#endif //CTLS_BYTES_H
