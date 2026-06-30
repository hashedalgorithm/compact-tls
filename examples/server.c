/*
 * cTLS example server.
 *
 * Binds a UDP socket, waits for a ClientHello, runs the server-side
 * handshake to completion, then exits.
 *
 * Usage:  ./compact_tls [port]
 * Default: 4433
 *
 * Wireshark filter:  udp.port == 4433
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
static struct sockaddr_in g_client_addr;
static socklen_t g_client_addr_len = sizeof(g_client_addr);
static int g_client_known = 0;

static ctls_status_t udp_send(uint8_t *buffer, ctls_size_t length) {
    if (!g_client_known) {
        fprintf(stderr, "[transport] send before client address known\n");
        return CTLS_STATUS_TRANSPORT_SEND_FAILED;
    }
    ssize_t sent = sendto(g_sock,
                          buffer,
                          length,
                          0,
                          (struct sockaddr *) &g_client_addr,
                          g_client_addr_len);
    if (sent < 0) {
        fprintf(stderr, "send: %s\n", strerror(errno));
        return CTLS_STATUS_TRANSPORT_SEND_FAILED;
    }
    printf("[transport] sent %zd bytes\n", sent);
    return CTLS_STATUS_SUCCESS;
}

static ctls_status_t udp_receive(uint8_t *buffer, ctls_size_t *length, ctls_size_t size) {
    ssize_t received = recvfrom(g_sock,
                                buffer,
                                size,
                                0,
                                (struct sockaddr *) &g_client_addr,
                                &g_client_addr_len);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "[transport] recv timeout\n");
        } else {
            fprintf(stderr, "recv: %s\n", strerror(errno));
        }
        return CTLS_STATUS_TRANSPORT_RECV_FAILED;
    }
    g_client_known = 1;
    *length = (ctls_size_t) received;

    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &g_client_addr.sin_addr, addr_str, sizeof(addr_str));
    printf("[transport] received %zd bytes from %s:%d\n",
           received, addr_str, ntohs(g_client_addr.sin_port));
    return CTLS_STATUS_SUCCESS;
}

int main(void) {
    int port = 4433;

    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sock < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 1;
    }

    int reuse = 1;
    setsockopt(g_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    /* 10-second receive timeout */
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t) port),
        .sin_addr   = {.s_addr = INADDR_ANY},
    };
    if (bind(g_sock, (struct sockaddr *) &bind_addr, sizeof(bind_addr)) < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        close(g_sock);
        return 1;
    }

    printf("listening on 0.0.0.0:%d\n", port);

    ctls_transport_t transport = {.recd_send = udp_send, .recd_receive = udp_receive};

    ctls_context_t ctx;
    ctls_status_t result = ctls_context_init(&ctx, &transport);
    if (result != CTLS_STATUS_SUCCESS) {
        fprintf(stderr, "ctls_context_init failed: 0x%04X\n", result);
        close(g_sock);
        return 1;
    }
    printf("context initialized\n");

    result = ctls_accept(&ctx);
    if (result != CTLS_STATUS_SUCCESS) {
        fprintf(stderr, "ctls_accept: 0x%04X\n", result);
    } else {
        printf("handshake complete\n");

        uint8_t wire_buf[CTLS_SIZE_WIRE_BUFFER];
        uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
        memset(plaintext, 0, sizeof(plaintext));
        result = ctls_read(wire_buf, plaintext, sizeof(plaintext) - 1, CTLS_ENTITY_CLIENT);
        if (result != CTLS_STATUS_SUCCESS) {
            fprintf(stderr, "ctls_read: 0x%04X\n", result);
        } else {
            printf("received: %s\n", (char *)plaintext);
        }
    }

    close(g_sock);
    return result == CTLS_STATUS_SUCCESS ? 0 : 1;
}
