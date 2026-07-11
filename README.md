# compact_tls

A compact TLS 1.3 implementation (cTLS) based
on [draft-ietf-tls-ctls](https://datatracker.ietf.org/doc/draft-ietf-tls-ctls/). Both peers share a pre-negotiated
template (profile) that eliminates redundant wire bytes from the TLS handshake.

## Prerequisites

- CMake ≥ 4.1
- C11 compiler (clang or gcc)
- Internet access on first configure (or a local mirror of the URL below)

[Mbed TLS](https://github.com/Mbed-TLS/mbedtls)'s PSA Crypto backend (`tfpsacrypto`) is fetched and built from source automatically via CMake `FetchContent` — no system package required, no version to match. This also means it works unmodified on Linux/WSL, where Mbed TLS 4.x isn't in any distro's package manager yet. See `CMakeLists.txt` for the pinned version.

## Build

Role is selected at configure time. Exactly one of `CTLS_CLIENT` / `CTLS_SERVER` must be `ON`.

```sh
./build.sh          # client (default) → build/client/compact_tls
./build.sh client   # same
./build.sh server   # server build    → build/server/compact_tls
```

Or manually:

```sh
# Client
cmake -B build/client -DCTLS_CLIENT=ON -DCTLS_SERVER=OFF
cmake --build build/client

# Server
cmake -B build/server -DCTLS_CLIENT=OFF -DCTLS_SERVER=ON
cmake --build build/server
```

Transport is also selected at configure time. Exactly one of `CTLS_STREAM` /
`CTLS_DATAGRAM` must be `ON` — default is `CTLS_DATAGRAM` (UDP-like framing,
matching the UDP sockets in `examples/`). Set `CTLS_STREAM=ON` for TCP-like transports; this
switches the unified header's sequence-number framing and the HKDF label prefix
(`"Sctls "` vs `"Dctls "`, draft-ietf-tls-ctls §2.2/§2.3.2). Not exposed via `build.sh` — pass it to `cmake`
directly:

```sh
cmake -B build/client -DCTLS_CLIENT=ON -DCTLS_SERVER=OFF \
      -DCTLS_STREAM=ON -DCTLS_DATAGRAM=OFF
cmake --build build/client
```

## Configuration

Set the profile in `include/ctls/config.h` to match the peer:

```c
#define CTLS_PROFILE_ID  0x01
```

See `profile-registry.md` for available profile IDs and their algorithm combinations.

## Running the example client

```sh
# Connect to default address (127.0.0.1:4433)
./build/<client/server>/compact_tls

# Connect to a specific host and port
./build/<client/server>/compact_tls <host> <port>
```

With no server running, the client sends a ClientHello and exits after a 2-second receive timeout. The packet is visible
in Wireshark with filter `udp.port == 4433`.

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