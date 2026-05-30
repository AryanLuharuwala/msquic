/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Self-contained 127.0.0.1 loopback demo for the "single layer" MsQuic
    wrapper (src/wrapper/quic.h). It:

      1. Starts a listener whose on_accept callback echoes whatever it receives
         back to the peer (fread/fwrite-style, using the blocking quic_recv).
      2. Connects a client to that listener.
      3. Sends a buffer, blocking-receives the echo, and asserts equality.

    TLS / certificate note: QUIC requires TLS 1.3, so the listener needs a
    certificate + key. Generate a throwaway self-signed pair before running:

        openssl req -nodes -new -x509 -keyout /tmp/quicwrap.key -out /tmp/quicwrap.cert

    The client uses the wrapper's default "insecure" mode (no cert validation),
    which is appropriate for this local-only demo.

    Usage:

        echo [cert_file] [key_file]

    Defaults: /tmp/quicwrap.cert and /tmp/quicwrap.key.

--*/

#include "quic.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#define DEMO_PORT 14567
#define DEMO_ALPN "wrapper-echo"

//
// Server-side worker: blocks on quic_recv() for the accepted connection and
// echoes each chunk straight back with quic_send(). Runs until the stream/conn
// closes (quic_recv returns quic_err_closed).
//
static void*
EchoWorker(void* arg)
{
    quic_conn* conn = (quic_conn*)arg;
    uint8_t buf[4096];
    size_t n = 0;
    for (;;) {
        quic_result r = quic_recv(conn, buf, sizeof(buf), &n);
        if (r != quic_ok) {
            break; // closed or error
        }
        printf("[server] echoing %zu bytes\n", n);
        if (quic_send(conn, buf, n) != quic_ok) {
            break;
        }
    }
    return NULL;
}

//
// on_accept fires on a MsQuic worker thread; spin up a dedicated echo thread so
// we can use the blocking quic_recv without stalling the MsQuic worker.
//
static void
OnAccept(quic_listener* l, quic_conn* conn, void* user)
{
    (void)l; (void)user;
    printf("[server] accepted a connection\n");
    pthread_t th;
    pthread_create(&th, NULL, EchoWorker, conn);
    pthread_detach(th);
}

int
main(int argc, char** argv)
{
    const char* certFile = (argc > 1) ? argv[1] : "/tmp/quicwrap.cert";
    const char* keyFile  = (argc > 2) ? argv[2] : "/tmp/quicwrap.key";

    if (quic_init() != quic_ok) {
        printf("quic_init failed (status 0x%x)\n", quic_last_status());
        return 1;
    }

    quic_listen_opts lopts;
    memset(&lopts, 0, sizeof(lopts));
    lopts.alpn = DEMO_ALPN;
    lopts.cert_file = certFile;
    lopts.key_file = keyFile;
    lopts.on_accept = OnAccept;

    quic_listener* l = quic_listen(DEMO_PORT, &lopts);
    if (l == NULL) {
        printf("quic_listen failed (status 0x%x). Did you generate the cert?\n",
               quic_last_status());
        printf("  openssl req -nodes -new -x509 -keyout %s -out %s\n", keyFile, certFile);
        quic_cleanup();
        return 1;
    }
    printf("[server] listening on 127.0.0.1:%d\n", DEMO_PORT);

    quic_connect_opts copts;
    memset(&copts, 0, sizeof(copts));
    copts.alpn = DEMO_ALPN;
    copts.verify_cert = 0; // local demo: accept the self-signed cert

    quic_conn* c = quic_connect("127.0.0.1", DEMO_PORT, &copts);
    if (c == NULL) {
        printf("quic_connect failed (status 0x%x)\n", quic_last_status());
        quic_listener_close(l);
        quic_cleanup();
        return 1;
    }
    printf("[client] connecting...\n");

    const char* msg = "hello msquic single-layer wrapper";
    size_t msgLen = strlen(msg);

    if (quic_send(c, msg, msgLen) != quic_ok) {
        printf("[client] quic_send failed (status 0x%x)\n", quic_last_status());
        quic_close(c);
        quic_listener_close(l);
        quic_cleanup();
        return 1;
    }
    printf("[client] sent %zu bytes\n", msgLen);

    //
    // Blocking-receive the echo. The echo may arrive in multiple chunks, so
    // loop until we have the whole message back.
    //
    uint8_t rx[4096];
    size_t total = 0;
    while (total < msgLen) {
        size_t n = 0;
        quic_result r = quic_recv(c, rx + total, sizeof(rx) - total, &n);
        if (r != quic_ok) {
            printf("[client] quic_recv returned %d before full echo\n", r);
            break;
        }
        total += n;
    }
    printf("[client] received %zu bytes back\n", total);

    int ok = (total == msgLen) && (memcmp(rx, msg, msgLen) == 0);
    assert(ok && "echo mismatch");
    printf("[client] echo verified: \"%.*s\"\n", (int)total, rx);

    quic_close(c);
    quic_listener_close(l);
    quic_cleanup();

    printf("%s\n", ok ? "DEMO PASSED" : "DEMO FAILED");
    return ok ? 0 : 2;
}
