/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A thin, "single layer" convenience wrapper over the verbose MsQuic public
    API (src/inc/msquic.h). It collapses the registration / configuration /
    connection / stream dance into a handful of calls in the spirit of a simple
    socket or "quic.connect / quic.send / quic.recv" surface:

        quic_init();                       // open MsQuic + a Registration
        h = quic_connect(host, port, ...); // client connect + 1 bidi stream
        quic_send(h, buf, len);            // send on that stream
        quic_recv(h, buf, cap, &n);        // BLOCKING receive (cond-var pumped)
        quic_close(h);
        quic_cleanup();

    It also exposes a callback-first surface (on_connected / on_recv / on_closed)
    for event-driven call sites, and a tiny listener convenience
    (quic_listen + accept-via-callback) so a self-contained 127.0.0.1 loopback
    echo demo can be written without touching the raw MsQuic function table.

    The wrapper is intentionally a C-friendly surface (extern "C") even though
    it is implemented in C++. It is an OPTIONAL build target and does not affect
    msquic's default build (see src/wrapper/CMakeLists.txt).

    ----------------------------------------------------------------------------
    ALPN / TLS / certificate requirements (IMPORTANT)
    ----------------------------------------------------------------------------
    QUIC always runs over TLS 1.3, so even a loopback demo needs:

      * An ALPN string. Both client and server must agree on it. This wrapper
        defaults to "wrapper" but you may override it via quic_connect_opts /
        quic_listen_opts.

      * Server side: a certificate + private key. For local testing generate a
        self-signed pair with OpenSSL:

            openssl req -nodes -new -x509 -keyout server.key -out server.cert

        and pass the paths to quic_listen() (cert_file / key_file).

      * Client side: by default this wrapper sets
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION (the "insecure" toggle)
        so the self-signed server cert is accepted. This is fine for local
        testing ONLY. Set opts.verify_cert = true (or leave insecure = false)
        for production, where the server presents a CA-trusted certificate.

    ----------------------------------------------------------------------------
    Buffer ownership
    ----------------------------------------------------------------------------
    Received data is COPIED out of the MsQuic QUIC_BUFFERs into wrapper-owned
    storage before any callback fires or quic_recv() returns. The caller never
    sees a raw QUIC_BUFFER and never has to call StreamReceiveComplete; the
    wrapper completes the receive synchronously. The (buf, len) handed to
    on_recv is valid only for the duration of that callback.

    ----------------------------------------------------------------------------
    Receive delivery: on_recv vs quic_recv are MUTUALLY EXCLUSIVE
    ----------------------------------------------------------------------------
    Pick ONE receive path per connection. Each received chunk is BOTH appended
    to the FIFO that quic_recv() drains AND passed to on_recv (if set). If you
    register an on_recv callback AND also call quic_recv() on the same
    connection, every chunk is delivered twice (once to each path). Use on_recv
    for event-driven call sites, or quic_recv() for blocking call sites, but not
    both on the same connection.

    ----------------------------------------------------------------------------
    Connection ownership / cleanup (who calls quic_close)
    ----------------------------------------------------------------------------
    Every quic_conn must be released with EXACTLY ONE quic_close() call, on both
    the client and the server side:

      * Client (quic_connect): the caller owns the returned quic_conn and must
        quic_close() it when done (e.g. after its quic_send/quic_recv work, or
        after on_closed fires).

      * Server (quic_listen / on_accept): the quic_conn delivered to on_accept
        is wrapper-allocated, but its OWNERSHIP transfers to whoever consumes it
        (typically the worker thread started from on_accept). That consumer must
        quic_close() it exactly once when finished. The wrapper does NOT free
        accepted connections for you; skipping quic_close() leaks the quic_conn.

    quic_close() is safe to call after the peer has already closed the
    connection (i.e. after on_closed fired or after quic_recv() returned
    quic_err_closed): the underlying MsQuic handles are freed at most once and
    the quic_conn is always freed. It is NOT, however, safe to call quic_close()
    more than once on the same handle, nor from inside a wrapper callback.

--*/

#ifndef _QUIC_WRAPPER_H_
#define _QUIC_WRAPPER_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Opaque handle to a wrapped connection (client) or accepted connection
// (server side). One handle owns exactly one bidirectional stream.
//
typedef struct quic_conn quic_conn;

//
// Opaque handle to a listener.
//
typedef struct quic_listener quic_listener;

//
// Result codes. quic_ok == success. Non-zero values are failures; the raw
// MsQuic QUIC_STATUS is available via quic_last_status() for diagnostics.
//
typedef enum quic_result {
    quic_ok = 0,
    quic_err = 1,            // generic / MsQuic failure (see quic_last_status())
    quic_err_closed = 2,     // stream/connection closed before/while waiting
    quic_err_timeout = 3,    // (reserved) blocking wait timed out
    quic_err_again = 4       // no data yet (non-blocking style)
} quic_result;

//
// Per-connection event callbacks. All are optional (may be NULL). They are
// invoked on a MsQuic worker thread, so keep them short and do not call back
// into blocking wrapper APIs from inside them.
//
//   on_connected : handshake finished, stream is ready for quic_send().
//   on_recv      : peer sent (buf, len) bytes. Valid only during the call.
//                  Mutually exclusive with quic_recv(); see the header comment.
//   on_closed    : the connection (and its stream) are gone. After this fires
//                  the handle must not be used except for quic_close(). It does
//                  NOT free the handle for you: the owner must still call
//                  quic_close() exactly once (see "Connection ownership").
//
typedef void (*quic_on_connected)(quic_conn* conn, void* user);
typedef void (*quic_on_recv)(quic_conn* conn, const uint8_t* buf, size_t len, void* user);
typedef void (*quic_on_closed)(quic_conn* conn, void* user);

//
// Options for quic_connect(). Zero-initialize and override as needed; NULL is
// accepted by quic_connect() and means "all defaults".
//
typedef struct quic_connect_opts {
    const char* alpn;            // default "wrapper" if NULL
    int verify_cert;             // 0 (default) => insecure (accept any cert)
    uint64_t idle_timeout_ms;    // default 5000 if 0
    quic_on_connected on_connected;
    quic_on_recv on_recv;
    quic_on_closed on_closed;
    void* user;                  // opaque, passed back to callbacks
} quic_connect_opts;

//
// Called when a listener accepts a new connection. The wrapper has already
// created the quic_conn and wired its stream; register per-connection
// callbacks here (typically by storing them via quic_set_callbacks()).
//
typedef void (*quic_on_accept)(quic_listener* l, quic_conn* conn, void* user);

typedef struct quic_listen_opts {
    const char* alpn;            // default "wrapper" if NULL
    const char* cert_file;       // PEM cert path (required)
    const char* key_file;        // PEM private key path (required)
    uint64_t idle_timeout_ms;    // default 5000 if 0
    quic_on_accept on_accept;    // required for the server to do anything useful
    void* user;
} quic_listen_opts;

//
// Library lifecycle. quic_init() opens the MsQuic function table and a
// Registration (the execution context / worker threads). Call once before any
// other API. quic_cleanup() tears everything down; call last.
//
quic_result quic_init(void);
void        quic_cleanup(void);

//
// Client: open a Configuration (ALPN + TLS), open + start a Connection, open +
// start ONE bidirectional stream, and return a handle. Non-blocking: the
// handshake proceeds asynchronously. Use on_connected (or just call
// quic_send/quic_recv, which wait internally) to know when it is ready.
//
quic_conn* quic_connect(const char* host, uint16_t port, const quic_connect_opts* opts);

//
// Send len bytes on the connection's bidirectional stream. The data is copied
// internally, so buf may be reused/freed immediately on return. If the
// handshake has not completed yet this call blocks until it does (or fails).
//
quic_result quic_send(quic_conn* conn, const void* buf, size_t len);

//
// BLOCKING receive. Waits (on a condition variable fed by the receive
// callback) until at least one byte is available, then copies up to cap bytes
// into buf and stores the count in *out_n. Returns:
//   quic_ok          : *out_n bytes copied (1..cap).
//   quic_err_closed  : the stream/connection closed with no more data.
//   quic_err         : other failure.
//
quic_result quic_recv(quic_conn* conn, void* buf, size_t cap, size_t* out_n);

//
// BLOCKING receive with a per-call deadline. Identical to quic_recv() except it
// waits at most timeout_ms milliseconds for data to arrive. Returns:
//   quic_ok          : *out_n bytes copied (1..cap).
//   quic_err_closed  : the stream/connection closed with no more data.
//   quic_err_timeout : no data arrived within timeout_ms (*out_n set to 0).
//   quic_err         : other failure.
// timeout_ms < 0 means block forever (identical behavior to quic_recv()).
//
quic_result quic_recv_timeout(quic_conn* conn, void* buf, size_t cap, size_t* out_n, int timeout_ms);

//
// Replace the per-connection callbacks (handy from on_accept on the server
// side, where the connection is created by the wrapper).
//
void quic_set_callbacks(
    quic_conn* conn,
    quic_on_connected on_connected,
    quic_on_recv on_recv,
    quic_on_closed on_closed,
    void* user);

//
// Gracefully shut down and close a connection handle and its stream, and free
// the handle. Call EXACTLY ONCE per quic_conn (client and server side alike;
// see "Connection ownership / cleanup" above). Safe to call after the peer has
// already closed the connection (after on_closed / quic_err_closed) -- the
// MsQuic handles are freed at most once. Do NOT call it twice, and do NOT call
// it from inside a wrapper callback.
//
void quic_close(quic_conn* conn);

//
// Server: open a Configuration (ALPN + cert/key) and start a listener bound to
// the given UDP port on all local addresses. Accepted connections are
// delivered via opts->on_accept. Returns NULL on failure.
//
quic_listener* quic_listen(uint16_t port, const quic_listen_opts* opts);

//
// Stop and close a listener. Does not close connections it already accepted.
//
void quic_listener_close(quic_listener* l);

//
// Returns the raw MsQuic QUIC_STATUS from the most recent failing call on the
// current thread (for diagnostics / logging).
//
uint32_t quic_last_status(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _QUIC_WRAPPER_H_
