/*
 * cTLS example server.
 *
 * Waits for a ClientHello, runs the server-side handshake to completion,
 * then exchanges one application data message. Transport is hardcoded at
 * compile time by CTLS_TRANSPORT_RELIABLE / CTLS_TRANSPORT_UNRELIABLE
 * (config.h, set via CMake — see README's "Build" section): TCP
 * (SOCK_STREAM, listen/accept/send/recv) when reliable, UDP (SOCK_DGRAM,
 * recvfrom/sendto) when unreliable.
 *
 * Usage:  ./compact_tls  (port hardcoded below, no command-line args)
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

#if CTLS_TRANSPORT_RELIABLE

static int g_client_sock = -1;

static ctls_status_t transport_send(uint8_t *buffer, ctls_size_t length) {
    ssize_t sent = send(g_client_sock, buffer, length, 0);
    if (sent < 0) {
        fprintf(stderr, "send: %s\n", strerror(errno));
        return CTLS_STATUS_TRANSPORT_SEND_FAILED;
    }
    printf("[transport] sent %zd bytes\n", sent);
    return CTLS_STATUS_SUCCESS;
}

static ctls_status_t transport_receive(uint8_t *buffer, ctls_size_t *length, ctls_size_t size) {
    ssize_t received = recv(g_client_sock, buffer, size, 0);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "[transport] recv timeout\n");
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

#else /* CTLS_TRANSPORT_UNRELIABLE */

static struct sockaddr_in g_client_addr;
static socklen_t g_client_addr_len = sizeof(g_client_addr);
static int g_client_known = 0;

static ctls_status_t transport_send(uint8_t *buffer, ctls_size_t length) {
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

static ctls_status_t transport_receive(uint8_t *buffer, ctls_size_t *length, ctls_size_t size) {
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

#endif

int main(void) {
    int port = 4433;

#if CTLS_TRANSPORT_RELIABLE
    g_sock = socket(AF_INET, SOCK_STREAM, 0);
#else
    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
#endif
    if (g_sock < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 1;
    }

    int reuse = 1;
    setsockopt(g_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

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

#if CTLS_TRANSPORT_RELIABLE
    if (listen(g_sock, 1) < 0) {
        fprintf(stderr, "listen: %s\n", strerror(errno));
        close(g_sock);
        return 1;
    }

    struct sockaddr_in accepted_addr;
    socklen_t accepted_addr_len = sizeof(accepted_addr);
    g_client_sock = accept(g_sock, (struct sockaddr *) &accepted_addr, &accepted_addr_len);
    if (g_client_sock < 0) {
        fprintf(stderr, "accept: %s\n", strerror(errno));
        close(g_sock);
        return 1;
    }

    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &accepted_addr.sin_addr, addr_str, sizeof(addr_str));
    printf("accepted connection from %s:%d\n", addr_str, ntohs(accepted_addr.sin_port));

    /* 10-second receive timeout on the accepted connection */
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(g_client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#else
    /* 10-second receive timeout */
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    ctls_transport_t transport = {.recd_send = transport_send, .recd_receive = transport_receive};

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

#if CTLS_TRANSPORT_RELIABLE
    close(g_client_sock);
#endif
    close(g_sock);
    return result == CTLS_STATUS_SUCCESS ? 0 : 1;
}
