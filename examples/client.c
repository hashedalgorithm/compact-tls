/*
 * cTLS example client.
 *
 * Sends a ClientHello to a UDP server and exits. Useful for packet capture
 * in Wireshark before a real server is available.
 *
 * Usage:  ./compact_tls [host] [port]
 * Default: 127.0.0.1 4433
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

static int              g_sock = -1;
static struct sockaddr_in g_server_addr;

static ctls_status_t udp_send(uint8_t *buffer, ctls_size_t length) {
    ssize_t sent = sendto(g_sock, buffer, length, 0,
                          (struct sockaddr *)&g_server_addr,
                          sizeof(g_server_addr));
    if (sent < 0) {
        fprintf(stderr, "send: %s\n", strerror(errno));
        return CTLS_STATUS_TRANSPORT_SEND_FAILED;
    }
    printf("[transport] sent %zd bytes\n", sent);
    return CTLS_STATUS_SUCCESS;
}

static ctls_status_t udp_receive(uint8_t *buffer,
                                 ctls_size_t *length,
                                 ctls_size_t size) {
    ssize_t received = recv(g_sock, buffer, size, 0);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "[transport] recv timeout — no server response\n");
        } else {
            fprintf(stderr, "recv: %s\n", strerror(errno));
        }
        return CTLS_STATUS_TRANSPORT_RECV_FAILED;
    }
    *length = (ctls_size_t)received;
    printf("[transport] received %zd bytes\n", received);
    return CTLS_STATUS_SUCCESS;
}

int main(int argc, char *argv[]) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int         port = (argc > 2) ? atoi(argv[2]) : 4433;

    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sock < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 1;
    }

    /* 2-second receive timeout — exits cleanly when no server is present */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&g_server_addr, 0, sizeof(g_server_addr));
    g_server_addr.sin_family      = AF_INET;
    g_server_addr.sin_port        = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &g_server_addr.sin_addr) != 1) {
        fprintf(stderr, "invalid address: %s\n", host);
        close(g_sock);
        return 1;
    }

    printf("connecting to %s:%d\n", host, port);

    ctls_transport_t transport = {
        .recd_send    = udp_send,
        .recd_receive = udp_receive,
    };

    ctls_context_t ctx;
    ctls_status_t result = ctls_context_init(&ctx, &transport);
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
    }

    close(g_sock);
    return 0;
}
