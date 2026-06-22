# compact_tls

A compact TLS 1.3 implementation (cTLS) based on [draft-ietf-tls-ctls](https://datatracker.ietf.org/doc/draft-ietf-tls-ctls/). Both peers share a pre-negotiated template (profile) that eliminates redundant wire bytes from the TLS handshake.

## Prerequisites

- CMake ≥ 4.1
- C11 compiler (clang or gcc)
- [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) with PSA Crypto backend (`tfpsacrypto`)

Install Mbed TLS via Homebrew (macOS):

```sh
brew install mbedtls
```

## Build

```sh
cmake -B build
cmake --build build
```

This produces `build/compact_tls` — the example client binary.

## Configuration

Before building, set the role and profile in `include/ctls/config.h`:

```c
/* Role — exactly one must be 1 */
#define CTLS_CLIENT  1
#define CTLS_SERVER  0

/* Profile — must match the server's profile */
#define CTLS_PROFILE_ID  0x01
```

See `profile-registry.md` for available profile IDs and their algorithm combinations.

## Running the example client

```sh
# Connect to default address (127.0.0.1:4433)
./build/compact_tls

# Connect to a specific host and port
./build/compact_tls <host> <port>
```

With no server running, the client sends a ClientHello and exits after a 2-second receive timeout. The packet is visible in Wireshark with filter `udp.port == 4433`.

Expected output (no server):

```
connecting to 127.0.0.1:4433
context initialized
[transport] sent 74 bytes
ClientHello sent — no server response (expected). Check Wireshark.
```

## Using the library

Implement a transport and call `ctls_connect` (client) or `ctls_accept` (server):

```c
#include "ctls/ctls.h"

static ctls_status_t my_send(uint8_t *buf, ctls_size_t len) { /* ... */ }
static ctls_status_t my_recv(uint8_t *buf, ctls_size_t *len, ctls_size_t cap) { /* ... */ }

int main(void) {
    ctls_transport_t transport = {
        .recd_send    = my_send,
        .recd_receive = my_recv,
    };

    ctls_context_t ctx;
    ctls_status_t result = ctls_context_init(&ctx, &transport);
    if (result != CTLS_STATUS_SUCCESS) return 1;

    /* Client role (CTLS_CLIENT=1 in config.h) */
    result = ctls_connect(&ctx);

    /* Server role (CTLS_SERVER=1 in config.h) */
    /* result = ctls_accept(&ctx); */

    return result == CTLS_STATUS_SUCCESS ? 0 : 1;
}
```

## Project layout

```
include/ctls/   — public headers (ctls.h, crypto.h, types.h, …)
src/            — implementation (crypto, record, handshake, extensions)
examples/       — client.c example
profile-registry.md — profile ID → algorithm mapping
error-codes.md  — ctls_status_t value reference
```