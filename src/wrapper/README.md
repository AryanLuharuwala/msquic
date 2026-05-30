# MsQuic single-layer wrapper

A thin, well-documented convenience layer over the verbose MsQuic public API
(`src/inc/msquic.h`). It collapses the registration / configuration /
connection / stream dance into a `connect` / `send` / `recv` surface in the
spirit of a simple socket, plus a callback-first surface for event-driven code.

This is an **optional** build target. It does **not** affect the default msquic
build.

## API at a glance

```c
#include "quic.h"

quic_init();                                   // open MsQuic + a Registration

// --- client ---
quic_connect_opts opts = {0};
opts.alpn = "myproto";
opts.verify_cert = 0;                          // local testing: accept any cert
quic_conn* c = quic_connect("127.0.0.1", 4567, &opts);

quic_send(c, data, len);                       // send on the connection's stream

uint8_t buf[4096]; size_t n;
quic_recv(c, buf, sizeof(buf), &n);            // BLOCKING receive

quic_close(c);
quic_cleanup();
```

### Callback-first variant

Set `on_connected` / `on_recv` / `on_closed` in `quic_connect_opts` (or via
`quic_set_callbacks`) to drive things from MsQuic worker-thread callbacks
instead of (or in addition to) the blocking helpers:

```c
void on_recv(quic_conn* c, const uint8_t* buf, size_t len, void* user) { ... }

quic_connect_opts opts = {0};
opts.on_recv = on_recv;
quic_conn* c = quic_connect(host, port, &opts);
```

The blocking `quic_recv()` and the `on_recv` callback are both fed by the same
internal receive path, so you can mix them.

### Server / listener

```c
quic_listen_opts lopts = {0};
lopts.alpn = "myproto";
lopts.cert_file = "/tmp/server.cert";
lopts.key_file  = "/tmp/server.key";
lopts.on_accept = on_accept;                   // gets a ready quic_conn*
quic_listener* l = quic_listen(4567, &lopts);
```

## ALPN, TLS and certificates

QUIC always runs over TLS 1.3, so even a loopback demo needs these:

- **ALPN** – both ends must agree on the same ALPN string. Defaults to
  `"wrapper"`; override via the `alpn` option field.
- **Server certificate + key** – generate a self-signed pair for local testing:

  ```sh
  openssl req -nodes -new -x509 -keyout /tmp/quicwrap.key -out /tmp/quicwrap.cert
  ```

  and pass the paths as `cert_file` / `key_file` to `quic_listen()`.
- **Client validation** – by default the client sets
  `QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION` (the *insecure* toggle) so the
  self-signed cert is accepted. **Local testing only.** Set
  `opts.verify_cert = 1` for production, where the server presents a CA-trusted
  certificate.

## Buffer ownership

Received data is **copied** out of the MsQuic `QUIC_BUFFER`s into wrapper-owned
storage before any callback fires or `quic_recv()` returns. You never see a raw
`QUIC_BUFFER` and never call `StreamReceiveComplete`; the wrapper completes the
receive inline. The `(buf, len)` handed to `on_recv` is valid only for the
duration of that callback. Send buffers are copied internally, so the buffer you
pass to `quic_send()` may be reused or freed immediately on return.

## Building (optional target)

The wrapper is gated behind `QUIC_BUILD_WRAPPER`, which is **OFF** by default:

```sh
cmake -B build -DQUIC_BUILD_WRAPPER=ON
cmake --build build --target quic_wrapper quic_wrapper_echo
```

Building msquic itself requires its TLS submodule (`quictls`/OpenSSL) to be
present and built. On this laptop the full build is deferred — the actual
build + run of the example is handled by the **rtxserver** step. The wrapper and
example were validated here with a `-fsyntax-only` header check against the real
`src/inc/msquic.h`.

## Running the loopback echo demo

```sh
openssl req -nodes -new -x509 -keyout /tmp/quicwrap.key -out /tmp/quicwrap.cert
./quic_wrapper_echo            # or: ./quic_wrapper_echo <cert> <key>
```

The demo starts a listener that echoes, connects a client, sends a buffer,
blocking-receives it back, and asserts equality (prints `DEMO PASSED`).
