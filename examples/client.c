/*
 * cTLS example client.
 *
 * Runs the full client-side handshake against a server, then exchanges one
 * application data message. Transport is hardcoded at compile time by
 * CTLS_STREAM / CTLS_DATAGRAM (config.h, set via
 * CMake — see README's "Build" section): TCP (SOCK_STREAM, connect/send/recv)
 * when reliable, UDP (SOCK_DGRAM, sendto/recv) when unreliable.
 *
 * Usage:  ./compact_tls  (host/port hardcoded below, no command-line args)
 *
 * Wireshark filter:  tcp.port == 4433  (reliable)  |  udp.port == 4433  (unreliable)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "ctls/ctls.h"

static int g_sock = -1;

#if CTLS_STREAM

static ctls_status_t transport_send(uint8_t *buffer, ctls_size_t length) {
    ssize_t sent = send(g_sock, buffer, length, 0);
    if (sent < 0) {
        fprintf(stderr, "send: %s\n", strerror(errno));
        return CTLS_STATUS_TRANSPORT_SEND_FAILED;
    }
    printf("[transport] sent %zd bytes\n", sent);
    return CTLS_STATUS_SUCCESS;
}

static ctls_status_t transport_receive(uint8_t *buffer, ctls_size_t *length, ctls_size_t size) {
    ssize_t received = recv(g_sock, buffer, size, 0);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "[transport] recv timeout — no server response\n");
        } else {
            fprintf(stderr, "recv: %s\n", strerror(errno));
        }
        return CTLS_STATUS_TRANSPORT_RECV_FAILED;
    }
    if (received == 0) {
        fprintf(stderr, "[transport] connection closed by peer\n");
        return CTLS_STATUS_TRANSPORT_RECV_FAILED;
    }
    *length = (ctls_size_t) received;
    printf("[transport] received %zd bytes\n", received);
    return CTLS_STATUS_SUCCESS;
}

#else /* CTLS_DATAGRAM */

static struct sockaddr_in g_server_addr;

static ctls_status_t transport_send(uint8_t *buffer, ctls_size_t length) {
    ssize_t sent = sendto(g_sock,
                          buffer,
                          length,
                          0,
                          (struct sockaddr *) &g_server_addr,
                          sizeof(g_server_addr));
    if (sent < 0) {
        fprintf(stderr, "send: %s\n", strerror(errno));
        return CTLS_STATUS_TRANSPORT_SEND_FAILED;
    }
    printf("[transport] sent %zd bytes\n", sent);
    return CTLS_STATUS_SUCCESS;
}

static ctls_status_t transport_receive(uint8_t *buffer, ctls_size_t *length, ctls_size_t size) {
    ssize_t received = recv(g_sock, buffer, size, 0);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "[transport] recv timeout — no server response\n");
        } else {
            fprintf(stderr, "recv: %s\n", strerror(errno));
        }
        return CTLS_STATUS_TRANSPORT_RECV_FAILED;
    }
    *length = (ctls_size_t) received;
    printf("[transport] received %zd bytes\n", received);
    return CTLS_STATUS_SUCCESS;
}

#endif

int main(void) {
    const char *host = "127.0.0.1";
    int port = 4433;

#if CTLS_STREAM
    g_sock = socket(AF_INET, SOCK_STREAM, 0);
#else
    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
#endif
    if (g_sock < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 1;
    }

    /* 2-second receive timeout — exits cleanly when no server is present */
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "invalid address: %s\n", host);
        close(g_sock);
        return 1;
    }

    printf("connecting to %s:%d\n", host, port);

#if CTLS_STREAM
    if (connect(g_sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "connect: %s\n", strerror(errno));
        close(g_sock);
        return 1;
    }
#else
    g_server_addr = server_addr;
#endif

    ctls_transport_t transport = {.recd_send = transport_send, .recd_receive = transport_receive,};

    ctls_context_t ctx;
    ctls_status_t result = ctls_context_init(&ctx, &transport, "template.json");
    if (result != CTLS_STATUS_SUCCESS) {
        fprintf(stderr, "ctls_context_init failed: 0x%04X\n", result);
        close(g_sock);
        return 1;
    }
    printf("context initialized\n");

    result = ctls_connect(&ctx);
    /*
     * Expected result when no server is listening: ClientHello is sent
     * (visible in Wireshark), then recv times out and ctls_connect returns
     * CTLS_STATUS_TRANSPORT_RECV_FAILED. That is not an error here.
     */
    if (result == CTLS_STATUS_TRANSPORT_RECV_FAILED) {
        printf("ClientHello sent — no server response (expected). Check Wireshark.\n");
    } else if (result != CTLS_STATUS_SUCCESS) {
        fprintf(stderr, "ctls_connect: 0x%04X\n", result);
    } else {
        printf("handshake complete\n");

        static const uint8_t msg[] = "Hello world!!";
        result = ctls_write(msg, sizeof(msg) - 1, CTLS_ENTITY_CLIENT);
        if (result != CTLS_STATUS_SUCCESS) {
            fprintf(stderr, "ctls_write: 0x%04X\n", result);
        } else {
            printf("sent: %s\n", (char *)msg);
        }

        result = ctls_close(&ctx, CTLS_ENTITY_CLIENT);
        if (result != CTLS_STATUS_SUCCESS) {
            fprintf(stderr, "ctls_close: 0x%04X\n", result);
        } else {
            printf("close_notify sent\n");
        }
    }

    close(g_sock);
    return 0;
}
