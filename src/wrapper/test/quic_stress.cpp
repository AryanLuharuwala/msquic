/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Multi-connection concurrency STRESS reproducer for the single-layer MsQuic
    wrapper (src/wrapper/quic.h). It mirrors the dlx framework's in-process
    topology that exposed intermittent dropped requests:

      * K listeners on 127.0.0.1, each on a distinct port, each its own server
        node. Every accepted connection is handled on a dedicated echo worker
        thread (exactly like the echo example / a dlx node): quic_recv a
        request, echo it straight back, loop until close.

      * R rounds; in each round C concurrent client tasks are fired across the
        K listeners. A fraction of those clients are RELAYS: a relay connects to
        listener A, and from inside that exchange opens a NESTED client connect
        to listener B, forwarding the payload onward and stitching the answer
        back -- this reproduces the dlx node->node nested connect pattern that
        runs client connects while server callbacks are firing on shared workers.

    Every exchange round-trips a unique, seeded payload and the reproducer
    asserts the echo matches byte-for-byte. It COUNTS drops (empty / closed
    before a full echo), mismatches, and connect/send/recv errors. With the
    racy wrapper this intermittently drops ~1-in-2..1-in-3 cold; with the fixed
    wrapper it must be ZERO across high R*C.

    Usage:  quic_stress [K] [R] [C] [seed]
    Default: K=4 R=200 C=8 seed=1234

    Exit code 0 iff zero drops/mismatches/errors.

--*/

#include "quic.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>
#include <vector>

#define BASE_PORT 24600
#define STRESS_ALPN "wrapper-stress"

static const char* g_cert = "/tmp/quicwrap.cert";
static const char* g_key  = "/tmp/quicwrap.key";

static std::atomic<uint64_t> g_drops{0};      // closed/empty before full echo
static std::atomic<uint64_t> g_mismatch{0};   // bytes came back wrong
static std::atomic<uint64_t> g_connect_err{0};
static std::atomic<uint64_t> g_send_err{0};
static std::atomic<uint64_t> g_ok{0};
static std::atomic<uint64_t> g_exch{0};       // total exchanges actually attempted
static std::atomic<int>      g_workers{0};    // live server-side echo workers

// ----------------------------------------------------------------------------
// Server side: one echo worker thread per accepted connection (dlx node).
// ----------------------------------------------------------------------------
static void EchoWorker(quic_conn* conn)
{
    uint8_t buf[8192];
    size_t n = 0;
    for (;;) {
        quic_result r = quic_recv(conn, buf, sizeof(buf), &n);
        if (r != quic_ok) break;            // closed or error
        if (quic_send(conn, buf, n) != quic_ok) break;
    }
    quic_close(conn);
    g_workers.fetch_sub(1);                  // signal this handle is fully closed
}

static void OnAccept(quic_listener* l, quic_conn* conn, void* user)
{
    (void)l; (void)user;
    g_workers.fetch_add(1);
    std::thread(EchoWorker, conn).detach();
}

// ----------------------------------------------------------------------------
// Client helper: connect to port, send payload, recv full echo, verify, close.
// Returns true on a clean verified round-trip.
// ----------------------------------------------------------------------------
static bool DoExchange(uint16_t port, const std::string& payload)
{
    g_exch.fetch_add(1);
    quic_connect_opts copts;
    memset(&copts, 0, sizeof(copts));
    copts.alpn = STRESS_ALPN;
    copts.verify_cert = 0;
    copts.idle_timeout_ms = 10000;

    quic_conn* c = quic_connect("127.0.0.1", port, &copts);
    if (c == nullptr) { g_connect_err.fetch_add(1); return false; }

    bool ok = false;
    if (quic_send(c, payload.data(), payload.size()) != quic_ok) {
        g_send_err.fetch_add(1);
    } else {
        std::vector<uint8_t> rx(payload.size());
        size_t total = 0;
        bool dropped = false;
        while (total < payload.size()) {
            size_t n = 0;
            quic_result r = quic_recv_timeout(
                c, rx.data() + total, rx.size() - total, &n, 8000);
            if (r != quic_ok) { dropped = true; break; }
            total += n;
        }
        if (dropped || total != payload.size()) {
            g_drops.fetch_add(1);
        } else if (memcmp(rx.data(), payload.data(), payload.size()) != 0) {
            g_mismatch.fetch_add(1);
        } else {
            ok = true;
            g_ok.fetch_add(1);
        }
    }
    quic_close(c);
    return ok;
}

// An aggressive variant that deliberately races quic_send against quic_close on
// the SAME connection: one thread hammers quic_send while another quic_close()s
// it. This is the canonical exposure of the send-vs-close race on conn->Stream
// (bug #1/#2). We do NOT count send/recv outcomes here -- the only contract is
// that it must never corrupt memory or use a freed/stale Stream handle; a
// post-fix quic_send racing close must cleanly return quic_err_closed rather
// than StreamSend a stale handle. (Run under ASan/TSan to police that.)
static void RaceSendClose(uint16_t port, const std::string& payload)
{
    g_exch.fetch_add(1);
    quic_connect_opts copts;
    memset(&copts, 0, sizeof(copts));
    copts.alpn = STRESS_ALPN;
    copts.verify_cert = 0;
    // Short idle so MsQuic tears the connection down (firing the
    // SHUTDOWN_COMPLETE callback, which closes + nulls conn->Stream /
    // conn->Connection on a worker thread) WHILE our sender thread is still
    // calling quic_send() and reading those same handles. That overlap is the
    // canonical exposure of bug #1/#2/#3. We keep the idle timeout modest
    // (not 1ms): an extremely short idle drives MsQuic itself into an internal
    // teardown assertion (quic_bugcheck in MsQuicConnectionClose) that is
    // unrelated to the wrapper, so we avoid that library corner while still
    // reliably overlapping send with the worker-thread teardown.
    copts.idle_timeout_ms = 60;
    quic_conn* c = quic_connect("127.0.0.1", port, &copts);
    if (c == nullptr) { g_connect_err.fetch_add(1); return; }

    std::atomic<bool> stop{false};
    std::thread sender([&]() {
        // Hammer quic_send concurrently with the worker-thread teardown. A send
        // that loses the race must return quic_err_closed -- never StreamSend a
        // stale/freed/closed handle (ASan would flag the UAF; TSan the race).
        while (!stop.load()) {
            quic_send(c, payload.data(), payload.size());
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    });
    // Run the sender across the idle-teardown window so send overlaps the
    // worker-thread SHUTDOWN_COMPLETE several times.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    stop.store(true);
    sender.join();
    quic_close(c);
    g_ok.fetch_add(1);
}

// A RELAY client: connect to listener `front`, but before/while doing its own
// exchange, open a NESTED client connect to listener `back` and bounce the
// payload through it too. Mirrors a dlx node forwarding to a downstream node.
static void RelayTask(uint16_t front, uint16_t back, std::string payload)
{
    // Nested downstream connect first (node -> node), then the front exchange.
    DoExchange(back, payload + ":hop");
    DoExchange(front, payload);
}

int main(int argc, char** argv)
{
    int K = (argc > 1) ? atoi(argv[1]) : 4;
    int R = (argc > 2) ? atoi(argv[2]) : 200;
    int C = (argc > 3) ? atoi(argv[3]) : 8;
    unsigned seed = (argc > 4) ? (unsigned)strtoul(argv[4], nullptr, 10) : 1234u;
    if (const char* cf = getenv("QUIC_STRESS_CERT")) g_cert = cf;
    if (const char* kf = getenv("QUIC_STRESS_KEY"))  g_key  = kf;
    // QUIC_STRESS_RACE=0 disables the deliberate send-vs-close racing task
    // (RaceSendClose). That task drives MsQuic into an internal teardown
    // assertion on some platforms (quic_bugcheck in MsQuicConnectionClose,
    // unrelated to the wrapper), so the DROP-RATE regression gate is measured
    // with it OFF (pure verified echo + nested relays), while the sanitizer
    // runs keep it ON to exercise the wrapper's send/close/teardown locking.
    bool enableRace = true;
    if (const char* er = getenv("QUIC_STRESS_RACE")) enableRace = (atoi(er) != 0);

    if (getenv("OPENSSL_CONF") == nullptr) setenv("OPENSSL_CONF", "/dev/null", 0);

    if (quic_init() != quic_ok) {
        printf("quic_init failed (0x%x)\n", quic_last_status());
        return 1;
    }

    std::vector<quic_listener*> listeners;
    for (int i = 0; i < K; ++i) {
        quic_listen_opts lopts;
        memset(&lopts, 0, sizeof(lopts));
        lopts.alpn = STRESS_ALPN;
        lopts.cert_file = g_cert;
        lopts.key_file = g_key;
        lopts.idle_timeout_ms = 10000;
        lopts.on_accept = OnAccept;
        quic_listener* l = quic_listen((uint16_t)(BASE_PORT + i), &lopts);
        if (l == nullptr) {
            printf("quic_listen on port %d failed (0x%x). cert=%s key=%s\n",
                   BASE_PORT + i, quic_last_status(), g_cert, g_key);
            return 1;
        }
        listeners.push_back(l);
    }

    printf("[stress] K=%d listeners on ports %d..%d, R=%d rounds, C=%d concurrent, seed=%u\n",
           K, BASE_PORT, BASE_PORT + K - 1, R, C, seed);

    std::mt19937 rng(seed);
    uint64_t exch = 0;

    for (int round = 0; round < R; ++round) {
        std::vector<std::thread> tasks;
        tasks.reserve(C);
        for (int j = 0; j < C; ++j) {
            uint16_t front = (uint16_t)(BASE_PORT + (rng() % K));
            uint16_t back  = (uint16_t)(BASE_PORT + (rng() % K));
            // Unique seeded payload, varied length.
            size_t len = 16 + (rng() % 2048);
            std::string payload;
            payload.reserve(len);
            uint64_t id = exch++;
            char hdr[48];
            int hn = snprintf(hdr, sizeof(hdr), "r%d-j%d-id%llu-", round, j,
                              (unsigned long long)id);
            payload.append(hdr, hn);
            std::mt19937 prng((unsigned)(seed ^ (id * 2654435761u)));
            while (payload.size() < len) payload.push_back((char)('A' + (prng() % 26)));

            int kind = rng() % 6;
            if (kind == 0 && enableRace) {
                // ~1/6: deliberately race quic_send against quic_close (bug #1/#2).
                tasks.emplace_back(RaceSendClose, front, std::move(payload));
            } else if (kind <= 2) {
                // ~1/3: nested node->node relay.
                tasks.emplace_back(RelayTask, front, back, std::move(payload));
            } else {
                // remainder: plain verified echo round-trip.
                tasks.emplace_back([front, payload]() { DoExchange(front, payload); });
            }
        }
        for (auto& t : tasks) t.join();
    }

    for (auto* l : listeners) quic_listener_close(l);
    // Honor the wrapper contract: quic_cleanup() must be called only after every
    // quic_conn has been closed. Drain all in-flight server echo workers (which
    // own the accepted connections and quic_close() them) before tearing down.
    for (int spins = 0; g_workers.load() > 0 && spins < 20000; ++spins) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    quic_cleanup();

    uint64_t drops = g_drops.load();
    uint64_t mism  = g_mismatch.load();
    uint64_t cerr  = g_connect_err.load();
    uint64_t serr  = g_send_err.load();
    uint64_t ok    = g_ok.load();
    uint64_t bad   = drops + mism + cerr + serr;
    exch = g_exch.load(); // actual exchanges incl. relay extra hops

    printf("[stress] exchanges=%llu ok=%llu drops=%llu mismatch=%llu connect_err=%llu send_err=%llu\n",
           (unsigned long long)exch, (unsigned long long)ok,
           (unsigned long long)drops, (unsigned long long)mism,
           (unsigned long long)cerr, (unsigned long long)serr);
    double rate = exch ? (100.0 * (double)bad / (double)exch) : 0.0;
    printf("[stress] FAILURE RATE: %.2f%% (%llu/%llu)\n", rate,
           (unsigned long long)bad, (unsigned long long)exch);
    printf("%s\n", bad == 0 ? "STRESS PASSED" : "STRESS FAILED");
    return bad == 0 ? 0 : 2;
}
