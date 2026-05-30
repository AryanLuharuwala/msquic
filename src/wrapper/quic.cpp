/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implementation of the "single layer" MsQuic wrapper declared in quic.h.

    Design notes:
      * One global MsQuic function table + Registration are created by
        quic_init() and shared by all handles.
      * Each quic_conn owns one Connection handle and (lazily, on the server
        side) one Stream handle. The wrapper translates MsQuic's
        QUIC_CONNECTION_EVENT / QUIC_STREAM_EVENT callbacks into the simple
        on_connected / on_recv / on_closed surface and into a thread-safe byte
        FIFO that quic_recv() blocks on.
      * Received QUIC_BUFFERs are copied into the FIFO synchronously inside the
        RECEIVE callback, so the wrapper returns the default status and lets
        MsQuic reclaim the buffers immediately (no pended receive / no explicit
        StreamReceiveComplete needed). See quic.h "Buffer ownership".

    Every MsQuic symbol used here was verified against src/inc/msquic.h:
      QUIC_API_TABLE members SetCallbackHandler, RegistrationOpen/Close,
      ConfigurationOpen/Close/LoadCredential, ListenerOpen/Start/Close,
      ConnectionOpen/Start/Shutdown/Close/SetConfiguration,
      StreamOpen/Start/Send/Shutdown/Close; MsQuicOpen2 / MsQuicClose macros;
      QUIC_STREAM_EVENT.RECEIVE { Buffers, BufferCount, TotalBufferLength };
      QUIC_CONNECTION_EVENT.PEER_STREAM_STARTED.Stream; QUIC_BUFFER { Length,
      Buffer }; flag enums QUIC_SEND_FLAG_NONE, QUIC_STREAM_OPEN_FLAG_NONE,
      QUIC_STREAM_START_FLAG_NONE, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
      QUIC_CONNECTION_SHUTDOWN_FLAG_NONE; credential flags
      QUIC_CREDENTIAL_FLAG_CLIENT / _NO_CERTIFICATE_VALIDATION; and the
      QuicAddrSetFamily / QuicAddrSetPort helpers from msquic_posix.h.

--*/

#define _CRT_SECURE_NO_WARNINGS 1

#include "quic.h"
#include "msquic.h"

#include <cstdlib>
#include <cstring>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>

//
// Global library state, created by quic_init().
//
namespace {

const QUIC_API_TABLE* g_MsQuic = nullptr;
HQUIC g_Registration = nullptr;

thread_local uint32_t t_LastStatus = QUIC_STATUS_SUCCESS;

inline void SetLastStatus(QUIC_STATUS s) { t_LastStatus = (uint32_t)s; }

//
// Build a QUIC_BUFFER pointing at an ALPN string (default "wrapper").
//
struct AlpnHolder {
    std::string str;
    QUIC_BUFFER buf;
    explicit AlpnHolder(const char* alpn) : str(alpn ? alpn : "wrapper") {
        buf.Length = (uint32_t)str.size();
        buf.Buffer = (uint8_t*)str.data();
    }
};

} // namespace

//
// The wrapped connection. Holds the Connection + Stream handles, the simple
// callbacks, and a byte FIFO plus sync primitives that back quic_recv().
//
struct quic_conn {
    HQUIC Connection = nullptr;
    HQUIC Stream = nullptr;
    HQUIC Configuration = nullptr; // owned only on the client side
    bool IsServerSide = false;

    quic_on_connected on_connected = nullptr;
    quic_on_recv on_recv = nullptr;
    quic_on_closed on_closed = nullptr;
    void* user = nullptr;

    std::mutex mtx;
    std::condition_variable cv;
    std::deque<uint8_t> rxfifo;  // received bytes awaiting quic_recv()
    bool connected = false;
    bool stream_ready = false;
    bool closed = false;         // peer/stream/conn shut down: no more data
};

struct quic_listener {
    HQUIC Listener = nullptr;
    HQUIC Configuration = nullptr;
    quic_on_accept on_accept = nullptr;
    void* user = nullptr;
};

// ----------------------------------------------------------------------------
// Stream callback: translate RECEIVE into the FIFO + on_recv, and shutdowns
// into the "closed" signal.
// ----------------------------------------------------------------------------
_Function_class_(QUIC_STREAM_CALLBACK)
static QUIC_STATUS QUIC_API
StreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event)
{
    auto* c = (quic_conn*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        //
        // Copy every QUIC_BUFFER out into the FIFO, then deliver on_recv (if
        // set) per buffer. Returning SUCCESS completes the receive inline, so
        // MsQuic reclaims the buffers right after this returns.
        //
        {
            std::lock_guard<std::mutex> lk(c->mtx);
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                const QUIC_BUFFER* b = &Event->RECEIVE.Buffers[i];
                c->rxfifo.insert(c->rxfifo.end(), b->Buffer, b->Buffer + b->Length);
            }
        }
        c->cv.notify_all();
        if (c->on_recv) {
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                const QUIC_BUFFER* b = &Event->RECEIVE.Buffers[i];
                c->on_recv(c, b->Buffer, b->Length, c->user);
            }
        }
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // Free the per-send QUIC_BUFFER block we allocated in quic_send().
        //
        free(Event->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // No more data will arrive from the peer on this stream.
        //
        {
            std::lock_guard<std::mutex> lk(c->mtx);
            c->closed = true;
        }
        c->cv.notify_all();
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            g_MsQuic->StreamClose(Stream);
            c->Stream = nullptr;
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// Connection callback: drives on_connected / on_closed and, on the server
// side, adopts the peer-initiated stream.
// ----------------------------------------------------------------------------
_Function_class_(QUIC_CONNECTION_CALLBACK)
static QUIC_STATUS QUIC_API
ConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event)
{
    auto* c = (quic_conn*)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        {
            std::lock_guard<std::mutex> lk(c->mtx);
            c->connected = true;
        }
        c->cv.notify_all();
        if (c->on_connected) {
            c->on_connected(c, c->user);
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // Server side: the client opened the bidi stream. Adopt it and wire the
        // stream callback. MUST set the handler before returning.
        //
        c->Stream = Event->PEER_STREAM_STARTED.Stream;
        g_MsQuic->SetCallbackHandler(c->Stream, (void*)StreamCallback, c);
        {
            std::lock_guard<std::mutex> lk(c->mtx);
            c->stream_ready = true;
        }
        c->cv.notify_all();
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // Free the MsQuic Connection handle and null it out FIRST, while no
        // wrapper thread can yet observe closed==true. This guarantees that
        // once a blocked quic_recv() wakes (below) and its caller proceeds to
        // quic_close()/delete the quic_conn, this MsQuic worker thread is no
        // longer touching *c -> no use-after-free. When AppCloseInProgress is
        // set, quic_close() already closed the handle, so we must not again.
        //
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            g_MsQuic->ConnectionClose(Connection);
            c->Connection = nullptr;
        }
        if (c->on_closed) {
            c->on_closed(c, c->user);
        }
        {
            //
            // Hold mtx across BOTH the state change and notify_all(). A blocked
            // quic_recv() can only return after re-acquiring mtx inside wait(),
            // which it cannot do until this scope releases the lock -> by then
            // notify_all() has finished touching c->cv. Without this, the woken
            // caller could delete the quic_conn (and its cv) while this thread
            // were still inside notify_all().
            //
            std::lock_guard<std::mutex> lk(c->mtx);
            c->closed = true;
            c->cv.notify_all();
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// Listener callback: create a wrapper conn for each new connection, hand the
// server Configuration to MsQuic, and notify the app via on_accept.
// ----------------------------------------------------------------------------
_Function_class_(QUIC_LISTENER_CALLBACK)
static QUIC_STATUS QUIC_API
ListenerCallback(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event)
{
    (void)Listener;
    auto* l = (quic_listener*)Context;
    QUIC_STATUS status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        auto* c = new quic_conn();
        c->IsServerSide = true;
        c->Connection = Event->NEW_CONNECTION.Connection;
        g_MsQuic->SetCallbackHandler(c->Connection, (void*)ConnectionCallback, c);
        status = g_MsQuic->ConnectionSetConfiguration(c->Connection, l->Configuration);
        if (QUIC_FAILED(status)) {
            delete c;
            break;
        }
        if (l->on_accept) {
            l->on_accept(l, c, l->user);
        }
        break;
    }
    default:
        break;
    }
    return status;
}

// ----------------------------------------------------------------------------
// Configuration helpers
// ----------------------------------------------------------------------------
static HQUIC
OpenClientConfiguration(const AlpnHolder& alpn, bool verifyCert, uint64_t idleMs)
{
    QUIC_SETTINGS settings;
    memset(&settings, 0, sizeof(settings));
    settings.IdleTimeoutMs = idleMs;
    settings.IsSet.IdleTimeoutMs = TRUE;

    QUIC_CREDENTIAL_CONFIG cred;
    memset(&cred, 0, sizeof(cred));
    cred.Type = QUIC_CREDENTIAL_TYPE_NONE;
    cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (!verifyCert) {
        // Insecure toggle for local testing: accept the self-signed server cert.
        cred.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    HQUIC cfg = nullptr;
    QUIC_STATUS status =
        g_MsQuic->ConfigurationOpen(
            g_Registration, &alpn.buf, 1, &settings, sizeof(settings), nullptr, &cfg);
    if (QUIC_FAILED(status)) { SetLastStatus(status); return nullptr; }

    status = g_MsQuic->ConfigurationLoadCredential(cfg, &cred);
    if (QUIC_FAILED(status)) {
        SetLastStatus(status);
        g_MsQuic->ConfigurationClose(cfg);
        return nullptr;
    }
    return cfg;
}

static HQUIC
OpenServerConfiguration(
    const AlpnHolder& alpn, const char* certFile, const char* keyFile, uint64_t idleMs)
{
    QUIC_SETTINGS settings;
    memset(&settings, 0, sizeof(settings));
    settings.IdleTimeoutMs = idleMs;
    settings.IsSet.IdleTimeoutMs = TRUE;
    // Allow the client to open the single bidirectional stream we expect.
    settings.PeerBidiStreamCount = 1;
    settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_CERTIFICATE_FILE certFileCfg;
    memset(&certFileCfg, 0, sizeof(certFileCfg));
    certFileCfg.CertificateFile = (char*)certFile;
    certFileCfg.PrivateKeyFile = (char*)keyFile;

    QUIC_CREDENTIAL_CONFIG cred;
    memset(&cred, 0, sizeof(cred));
    cred.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cred.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    cred.CertificateFile = &certFileCfg;

    HQUIC cfg = nullptr;
    QUIC_STATUS status =
        g_MsQuic->ConfigurationOpen(
            g_Registration, &alpn.buf, 1, &settings, sizeof(settings), nullptr, &cfg);
    if (QUIC_FAILED(status)) { SetLastStatus(status); return nullptr; }

    status = g_MsQuic->ConfigurationLoadCredential(cfg, &cred);
    if (QUIC_FAILED(status)) {
        SetLastStatus(status);
        g_MsQuic->ConfigurationClose(cfg);
        return nullptr;
    }
    return cfg;
}

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------
extern "C" {

quic_result quic_init(void)
{
    if (g_MsQuic != nullptr) {
        return quic_ok; // already initialized
    }
    QUIC_STATUS status = MsQuicOpen2(&g_MsQuic);
    if (QUIC_FAILED(status)) { SetLastStatus(status); return quic_err; }

    const QUIC_REGISTRATION_CONFIG regConfig =
        { "quic_wrapper", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    status = g_MsQuic->RegistrationOpen(&regConfig, &g_Registration);
    if (QUIC_FAILED(status)) {
        SetLastStatus(status);
        MsQuicClose(g_MsQuic);
        g_MsQuic = nullptr;
        return quic_err;
    }
    return quic_ok;
}

void quic_cleanup(void)
{
    if (g_MsQuic == nullptr) {
        return;
    }
    if (g_Registration != nullptr) {
        // Blocks until all child objects (connections/streams) are closed.
        g_MsQuic->RegistrationClose(g_Registration);
        g_Registration = nullptr;
    }
    MsQuicClose(g_MsQuic);
    g_MsQuic = nullptr;
}

void quic_set_callbacks(
    quic_conn* conn,
    quic_on_connected on_connected,
    quic_on_recv on_recv,
    quic_on_closed on_closed,
    void* user)
{
    if (conn == nullptr) return;
    conn->on_connected = on_connected;
    conn->on_recv = on_recv;
    conn->on_closed = on_closed;
    conn->user = user;
}

quic_conn* quic_connect(const char* host, uint16_t port, const quic_connect_opts* opts)
{
    if (g_MsQuic == nullptr || host == nullptr) {
        return nullptr;
    }
    quic_connect_opts defaults;
    memset(&defaults, 0, sizeof(defaults));
    if (opts == nullptr) opts = &defaults;

    AlpnHolder alpn(opts->alpn);
    uint64_t idleMs = opts->idle_timeout_ms ? opts->idle_timeout_ms : 5000;

    HQUIC cfg = OpenClientConfiguration(alpn, opts->verify_cert != 0, idleMs);
    if (cfg == nullptr) {
        return nullptr;
    }

    auto* c = new quic_conn();
    c->Configuration = cfg;
    c->on_connected = opts->on_connected;
    c->on_recv = opts->on_recv;
    c->on_closed = opts->on_closed;
    c->user = opts->user;

    QUIC_STATUS status =
        g_MsQuic->ConnectionOpen(g_Registration, ConnectionCallback, c, &c->Connection);
    if (QUIC_FAILED(status)) { SetLastStatus(status); goto fail; }

    // Open and start the single bidirectional stream up front (client side).
    status = g_MsQuic->StreamOpen(
        c->Connection, QUIC_STREAM_OPEN_FLAG_NONE, StreamCallback, c, &c->Stream);
    if (QUIC_FAILED(status)) { SetLastStatus(status); goto fail; }

    status = g_MsQuic->StreamStart(c->Stream, QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(status)) { SetLastStatus(status); goto fail; }
    c->stream_ready = true;

    // Kick off the connection. Handshake proceeds asynchronously.
    status = g_MsQuic->ConnectionStart(
        c->Connection, cfg, QUIC_ADDRESS_FAMILY_UNSPEC, host, port);
    if (QUIC_FAILED(status)) { SetLastStatus(status); goto fail; }

    return c;

fail:
    if (c->Stream) g_MsQuic->StreamClose(c->Stream);
    if (c->Connection) g_MsQuic->ConnectionClose(c->Connection);
    if (c->Configuration) g_MsQuic->ConfigurationClose(c->Configuration);
    delete c;
    return nullptr;
}

quic_result quic_send(quic_conn* conn, const void* buf, size_t len)
{
    if (conn == nullptr || g_MsQuic == nullptr) {
        return quic_err;
    }

    // Wait until the stream is usable (handshake done / stream adopted).
    {
        std::unique_lock<std::mutex> lk(conn->mtx);
        conn->cv.wait(lk, [&] { return conn->stream_ready || conn->closed; });
        if (conn->closed || conn->Stream == nullptr) {
            return quic_err_closed;
        }
    }

    // Allocate one block holding the QUIC_BUFFER header + payload. MsQuic owns
    // it until SEND_COMPLETE, where StreamCallback frees it.
    void* raw = malloc(sizeof(QUIC_BUFFER) + len);
    if (raw == nullptr) {
        SetLastStatus(QUIC_STATUS_OUT_OF_MEMORY);
        return quic_err;
    }
    auto* sb = (QUIC_BUFFER*)raw;
    sb->Buffer = (uint8_t*)raw + sizeof(QUIC_BUFFER);
    sb->Length = (uint32_t)len;
    memcpy(sb->Buffer, buf, len);

    QUIC_STATUS status =
        g_MsQuic->StreamSend(conn->Stream, sb, 1, QUIC_SEND_FLAG_NONE, /*ctx*/ raw);
    if (QUIC_FAILED(status)) {
        SetLastStatus(status);
        free(raw);
        return quic_err;
    }
    return quic_ok;
}

quic_result quic_recv(quic_conn* conn, void* buf, size_t cap, size_t* out_n)
{
    if (conn == nullptr || buf == nullptr || out_n == nullptr) {
        return quic_err;
    }
    *out_n = 0;

    std::unique_lock<std::mutex> lk(conn->mtx);
    conn->cv.wait(lk, [&] { return !conn->rxfifo.empty() || conn->closed; });

    if (conn->rxfifo.empty()) {
        // Closed with nothing buffered.
        return quic_err_closed;
    }

    size_t n = conn->rxfifo.size();
    if (n > cap) n = cap;
    for (size_t i = 0; i < n; ++i) {
        ((uint8_t*)buf)[i] = conn->rxfifo.front();
        conn->rxfifo.pop_front();
    }
    *out_n = n;
    return quic_ok;
}

void quic_close(quic_conn* conn)
{
    if (conn == nullptr) {
        return;
    }
    if (g_MsQuic != nullptr) {
        if (conn->Stream != nullptr) {
            g_MsQuic->StreamShutdown(conn->Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        }
        if (conn->Connection != nullptr) {
            g_MsQuic->ConnectionShutdown(conn->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            g_MsQuic->ConnectionClose(conn->Connection);
            conn->Connection = nullptr;
        }
        if (conn->Configuration != nullptr) {
            g_MsQuic->ConfigurationClose(conn->Configuration);
            conn->Configuration = nullptr;
        }
    }
    delete conn;
}

quic_listener* quic_listen(uint16_t port, const quic_listen_opts* opts)
{
    if (g_MsQuic == nullptr || opts == nullptr ||
        opts->cert_file == nullptr || opts->key_file == nullptr) {
        return nullptr;
    }
    AlpnHolder alpn(opts->alpn);
    uint64_t idleMs = opts->idle_timeout_ms ? opts->idle_timeout_ms : 5000;

    HQUIC cfg = OpenServerConfiguration(alpn, opts->cert_file, opts->key_file, idleMs);
    if (cfg == nullptr) {
        return nullptr;
    }

    auto* l = new quic_listener();
    l->Configuration = cfg;
    l->on_accept = opts->on_accept;
    l->user = opts->user;

    QUIC_STATUS status =
        g_MsQuic->ListenerOpen(g_Registration, ListenerCallback, l, &l->Listener);
    if (QUIC_FAILED(status)) { SetLastStatus(status); goto fail; }

    {
        QUIC_ADDR addr;
        memset(&addr, 0, sizeof(addr));
        QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_UNSPEC);
        QuicAddrSetPort(&addr, port);
        status = g_MsQuic->ListenerStart(l->Listener, &alpn.buf, 1, &addr);
        if (QUIC_FAILED(status)) { SetLastStatus(status); goto fail; }
    }

    return l;

fail:
    if (l->Listener) g_MsQuic->ListenerClose(l->Listener);
    if (l->Configuration) g_MsQuic->ConfigurationClose(l->Configuration);
    delete l;
    return nullptr;
}

void quic_listener_close(quic_listener* l)
{
    if (l == nullptr) {
        return;
    }
    if (g_MsQuic != nullptr) {
        if (l->Listener != nullptr) {
            g_MsQuic->ListenerClose(l->Listener);
            l->Listener = nullptr;
        }
        if (l->Configuration != nullptr) {
            g_MsQuic->ConfigurationClose(l->Configuration);
            l->Configuration = nullptr;
        }
    }
    delete l;
}

uint32_t quic_last_status(void)
{
    return t_LastStatus;
}

} // extern "C"
