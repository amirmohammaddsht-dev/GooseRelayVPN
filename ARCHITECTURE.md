# Architecture

This document is the technical companion to [README.md](README.md). The
README explains what GooseRelayVPN does and how to run it; this document
explains how it works internally — the wire format, the goroutine model,
the engineering decisions worth understanding before changing code.

Aimed at someone reading the codebase cold: a future maintainer, an
interviewer walking through it, or me in six months.

---

## Data flow

```
                 ┌──────────────────────────┐
                 │   Browser / app           │
                 │   (configured to use      │
                 │    SOCKS5 127.0.0.1:1080) │
                 └──────────┬───────────────┘
                            │  raw TCP bytes
                            ▼
   ┌───────────────────────────────────────────────────────┐
   │  goose-client  (your laptop)                          │
   │  ─────────────────────────────────────────────────    │
   │  internal/socks      RFC 1928 listener + VirtualConn  │
   │  internal/session    Per-conn tx buffer + rx queue    │
   │  internal/carrier    Long-poll loop, drains sessions  │
   │                      into AES-GCM-sealed batches      │
   └──────────┬────────────────────────────────────────────┘
              │  HTTPS POST  (SNI = www.google.com,
              │               body = base64(encrypted batch))
              ▼
   ┌───────────────────────────────────────────────────────┐
   │  Google Apps Script  (apps_script/Code.gs)            │
   │  ─────────────────────────────────────────────────    │
   │  doPost(e) forwards the body verbatim via             │
   │  UrlFetchApp.fetch(RELAY_URLS[i]).                    │
   │  Never decrypts. Never holds the AES key.             │
   └──────────┬────────────────────────────────────────────┘
              │  HTTP POST  http://YOUR.VPS.IP:8443/tunnel
              ▼
   ┌───────────────────────────────────────────────────────┐
   │  goose-server  (your VPS)                             │
   │  ─────────────────────────────────────────────────    │
   │  internal/exit       Decrypts batch, demuxes by       │
   │                      session_id, dials upstream       │
   │                      targets, pumps bytes back        │
   │                      through long-poll responses.     │
   └──────────┬────────────────────────────────────────────┘
              │  net.Dial("tcp", target)
              ▼
                    The actual destination.
```

Everything in flight between the laptop and the VPS is encrypted under
AES-256-GCM with a key only the two endpoints know. Apps Script is a
dumb forwarder — it sees an opaque blob in, an opaque blob out. To any
passive observer on the path from your laptop to Google, the traffic
looks like ordinary HTTPS to `www.google.com`.

---

## The wire format

Two layers: a **frame** (logical message for one tunneled connection)
and a **batch** (encrypted envelope containing many frames).

### Frame

The plaintext exchanged between client and server. One frame per
direction-of-data per session per drain cycle.

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│                       session_id (16 bytes)                  │
│                                                              │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│                         seq (uint64 BE)                      │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│     flags     │ target_len    │                              │
├───────────────┴───────────────┘                              │
│              target (target_len bytes; SYN frames only)      │
├──────────────────────────────────────────────────────────────┤
│                     payload_len (uint32 BE)                  │
├──────────────────────────────────────────────────────────────┤
│                  payload (payload_len bytes)                 │
└──────────────────────────────────────────────────────────────┘
```

Flags: `SYN` (0x01, first frame, carries Target), `FIN` (0x02, half-close),
`ACK` (0x04, keepalive / version probe), `RST` (0x08, peer has no state).

See [internal/frame/frame.go](internal/frame/frame.go) for the canonical
spec and the Marshal/Unmarshal implementations.

### Batch

The wire envelope. **One AES-GCM seal per batch**, not per frame —
this is one of the more consequential design decisions; see
[Single-seal-per-batch](#single-seal-per-batch-encoding) below.

```
base64( nonce (12B) || AES-GCM Seal( plaintext, key ) )

plaintext =
    flags     (1 byte)   0x00 raw | 0x01 DEFLATE | 0x02 Zstd
    client_id (16 bytes)
    u16 frame_count
    for each frame: u32 marshaled_len || marshaled_frame_bytes
    (everything after the flags byte may be zstd-compressed)
```

`client_id` is sent inside the encrypted plaintext, not as an HTTP
header, because the Apps Script forwarder only relays the request
body — headers do not survive the hop. Sealing it under AES-GCM also
means a passive observer of the relay traffic cannot tell two clients
apart by their IDs.

See [internal/frame/crypto.go](internal/frame/crypto.go).

---

## Threat model

The project exists to defeat a specific class of adversary: an ISP,
national firewall, or other on-path attacker that controls DNS
resolution, can redirect traffic via BGP or transparent proxying,
and may attempt TLS interception on traffic leaving the user's
network. The threat model that motivated this project was a
state-level filter doing all three at once: foreign domain names
resolved to network-operator-controlled IPs, and traffic that did
reach the open internet was DPI-inspected and selectively blocked.

Even under that level of filtering, a small set of Google service
IPs typically remain reachable. This tool routes through that gap:
by domain-fronting to those reachable Google IPs, traffic that
would otherwise be blocked is delivered as ordinary-looking Google
traffic.

### What it defends against

Each row names an attacker capability, the defense in the codebase
that addresses it, and what happens if the attack succeeds against
that defense.

| Capability | Defense | If the defense fails |
| --- | --- | --- |
| **DNS hijacking** — the adversary returns a poisoned A record for `script.google.com` | Hardcoded Google edge IP in `client_config.json`. The client dials this IP directly and never consults the local resolver for the front host. | No effect — there's no DNS lookup to hijack. |
| **TLS interception** on the outer hop | Standard TLS certificate validation against the system root CAs (Go stdlib default). The interceptor doesn't have Google's private key. | TLS handshake fails closed before any bytes are exchanged. |
| **Passive observation** of ciphertext | AES-256-GCM with a 32-byte key known only to the client and VPS. Apps Script never holds the key. | Nothing readable inside the AES-GCM security bound. |
| **Active tampering** of ciphertext in flight | The 16-byte GCM authentication tag is computed over the ciphertext at seal time. A modified byte fails `Open()`; the entire batch is rejected. | The batch is dropped (no corrupted bytes ever reach the session); the carrier retries on the next poll. |
| **Local DNS leak** — the laptop resolves the actual destination hostname and reveals what the user is browsing | The SOCKS5 listener registers a no-op resolver. Target hostnames travel through the tunnel as strings and are resolved on the VPS. | None — local DNS is never consulted for tunneled traffic. |
| **Traffic fingerprinting by destination IP** | All client → upstream traffic terminates at a Google edge IP, indistinguishable from ordinary Google use at the IP layer. | Out of scope for IP-layer fingerprinting; pattern-layer fingerprinting is addressed separately below. |

### As a VPN, too

The threat-model framing emphasizes defending against the *upstream*
adversary — the ISP between the user and the open internet. But the
same architecture also provides what people normally call "VPN
behavior" at the *downstream* end: destination sites and services
see the VPS's IP, not the user's.

- **IP masking.** Destination sites cannot identify the user by
  source IP. The VPS handles `net.Dial`; sites see only the VPS.
- **Geo-unblocking.** Services that block traffic from the user's
  region at the network level — cloud providers, app stores, banks,
  and the like — are reachable through a VPS in a permitted
  country. Buying a VPS in Germany or the Netherlands and pointing
  this tool at it gives the same destination-side IP as any other
  VPN in those countries.
- **DNS-from-VPS.** Because the SOCKS5 listener uses a no-op resolver
  (see [internal/socks/server.go](internal/socks/server.go)), even
  hostname lookups for the destination happen on the VPS. The user's
  local ISP never learns *what* the user is browsing.

### What it does NOT defend against

Listing these honestly is more important than over-claiming the scope
of what's covered. Each one is a real attack a determined adversary
could mount; this project does not address any of them.

- **A compromised VPS.** The exit holds half the AES key and dials
  targets on the user's behalf. An attacker with VPS root can
  decrypt traffic, log destinations, or inject responses. Treat the
  VPS as a trusted endpoint.
- **A compromised client machine.** The AES key sits in
  `client_config.json` on disk. Malware on the laptop reads it and
  the tunnel becomes transparent to that attacker.
- **A compelled or compromised Google account.** Apps Script never
  sees plaintext, but a sufficiently motivated adversary could
  subpoena Apps Script logs to see traffic *volume*, *timing*, and
  the existence of the deployment. Payloads remain encrypted; the
  *existence* of a tunnel does not.
- **Sophisticated protocol fingerprinting by DPI.** At the TCP/TLS
  layer this looks like HTTPS to Google. At the *pattern* layer —
  long-poll cadence, batch sizes, request frequency — it is
  identifiable by an adversary that builds a classifier on those
  signatures. Padding and timing-randomization mitigations are not
  implemented; that would be a substantial future project.
- **Quota exhaustion as denial of service.** Apps Script's
  per-account daily limit is a hard cap. An adversary with knowledge
  of the deployment IDs cannot decrypt traffic, but could probably
  saturate the quota by spamming the `/exec` URL.

### Why defense in depth, not defense in single

It is tempting to say "AES handles it." It does not — strip out any
one layer and the threat model degrades in a specific, observable
way:

- Remove AES-GCM → the adversary reads everything.
- Use raw AES-CTR instead of GCM → the adversary can corrupt
  traffic without being noticed. The GCM tag is what makes
  tampering visible.
- Remove TLS certificate validation → the adversary impersonates
  Google on the outer hop and serves its own batches that fail
  decryption on the client side. The tunnel breaks, but no
  plaintext is exposed.
- Remove the hardcoded Google IP → DNS hijacking redirects the
  client to the adversary's server.
- Remove the no-op SOCKS resolver → the adversary sees every
  hostname the user browses to in cleartext, even though it can't
  read the body of the responses.

The layers cover distinct capabilities a single adversary may exercise
simultaneously. They aren't redundancy; they're coverage.

---

## Package map

```
cmd/                            program entry points (thin)
├── client/                     goose-client: SOCKS5 listener + carrier
└── server/                     goose-server: HTTP listener + exit

internal/
├── protocol/                   wire-level constants both peers share
│                               (frame-payload cap, batch-frame caps,
│                                busy-mode threshold, probe payloads)
├── frame/                      frame Marshal/Unmarshal + AES-GCM
│   ├── frame.go                plaintext frame layout
│   ├── crypto.go               batch envelope: zstd + AES-GCM + base64
│   └── *_test.go
├── session/                    one logical TCP connection across the tunnel
│   ├── session.go              tx buffer, rx reassembly, transactional drain
│   └── *_test.go
├── socks/                      RFC 1928/1929 listener (uses go-socks5)
│   ├── server.go               Serve(), TCP_NODELAY/QUICKACK acceptor,
│   │                           IPv4/IPv6 listen-network detection
│   ├── conn.go                 VirtualConn: net.Conn over (RxChan, EnqueueTx)
│   └── quickack_{linux,other}  platform-conditional TCP_QUICKACK setter
├── carrier/                    client-side: the long-poll machinery
│   ├── client.go               Client struct, lifecycle, pollOnce, drainAll
│   ├── endpoints.go            relayEndpoint, picker, blacklist, markEndpoint*
│   ├── local_network.go        airplane-mode detection + recovery probe
│   ├── error_body.go           Apps Script HTML/JSON error-page classifier
│   ├── fronting.go             multi-SNI domain-fronted *http.Clients
│   ├── quota.go                per-deployment daily counters + doGet polling
│   ├── stats.go                periodic [stats] log line
│   └── diagnose.go             one-shot --pre-flight health probe
├── exit/                       server-side: the VPS handler
│   ├── exit.go                 Server struct, /tunnel + /healthz, drainAll
│   ├── dnscache.go             5-minute DNS cache + dialWithDNSCache
│   └── stats.go                periodic [stats] log line
└── config/                     JSON-on-disk → validated structs
    ├── client.go               clientFile → Client (with deployment-ID hints)
    └── server.go               serverFile → Server (legacy-key fallback)

apps_script/
└── Code.gs                     ~30-line forwarder, deployed as Apps Script

bench/                          loopback bench harness (Apps Script bypassed)
```

---

## Engineering decisions

### Single-seal-per-batch encoding

[`internal/frame/crypto.go:127`](internal/frame/crypto.go) wraps the
entire batch in one AES-GCM `Seal` rather than sealing each frame
individually. This costs O(1) nonce + tag per HTTP request instead of
O(N), and is what makes [`protocol.MaxFramePayload`](internal/protocol/protocol.go)
worth raising to 256 KB — without the per-frame crypto tax, fewer/larger
frames are strictly cheaper.

The cost: the entire batch is atomic. One bit-flip anywhere in the
ciphertext rejects the whole batch. The rollback path in
[`session.DrainTxLimitedTxn`](internal/session/session.go) makes this
acceptable — failed batches restore their pre-drain state.

### Zstd compression with raw fallback

[`internal/frame/crypto.go:147`](internal/frame/crypto.go) attempts
zstd compression on the plaintext, and falls back to raw if compression
does not shrink it. This wins ~30–65% on plain HTTP/JSON, breaks even on
TLS-wrapped traffic, and never costs bytes. The decoder accepts three
flag values: raw, DEFLATE (legacy peers), and zstd.

### Per-bucket idle-poll semaphore

[`internal/carrier/endpoints.go`](internal/carrier/endpoints.go) —
`pickIdleEndpoint` and `releaseBucketSlot`. Apps Script throttles
concurrent UrlFetchApp invocations *per Google account*, not per
deployment. So we group deployments by their `account` label and cap
how many concurrent idle long-polls each bucket can hold (default 2).
Active polls (carrying TX) bypass the cap because they return quickly.
This is what was breaking under "issue #56" — too many idle long-polls
to one account were triggering Google's anti-abuse and serving HTML
error pages instead of relayed bytes.

### Classified endpoint backoff

[`internal/carrier/endpoints.go`](internal/carrier/endpoints.go) —
the family of `markEndpoint*` functions. Different failure classes get
different starting backoff tiers:

| Failure          | Tier              | Why                                         |
| ---------------- | ----------------- | ------------------------------------------- |
| Transient (5xx)  | 3 s, exponential  | Likely recovers in seconds                  |
| 429 rate-limit   | Floor at 24 s     | Self-heals in ~tens of seconds              |
| 403 quota        | Floor at 5 min    | Persists until midnight Pacific             |
| Hard (in body)   | Floor at 5 min    | Quota/auth surfaced inside an HTML 200      |
| Local-offline    | 15 s, no ramp     | Clears the moment a TCP probe succeeds      |

The "hard inside an HTML 200" case is why
[`error_body.go`](internal/carrier/error_body.go) exists: Apps Script
sometimes returns its error pages with HTTP 200, and the classifier
maps the body text (quota / auth / admin policy / transient Google
error) to the right backoff tier and a user-actionable log message.

### Multi-SNI fronting with TLS 1.3 ticket prewarm

[`internal/carrier/fronting.go`](internal/carrier/fronting.go) creates
one `*http.Client` per SNI host, each with its own TLS session-ticket
cache. The non-obvious bit is `prewarmFrontedClients`: in TLS 1.3 the
server sends `NewSessionTicket` *after* the handshake completes, on
the data channel. Closing the connection immediately after
`HandshakeContext` drops the ticket on the floor. The prewarm dial
issues a tiny read with a short deadline; the read errors out, but by
then the crypto/tls layer has consumed and cached the ticket. The
first real poll resumes the session instead of doing a full handshake,
saving ~140 ms.

### Multi-client isolation via clientID

[`internal/exit/exit.go`](internal/exit/exit.go) — `sessionOwners`,
`pendingRSTs`, `pendingCtrl`, `activity`. The exit server can host
several clients at once. Frames are sealed with a per-process 16-byte
`clientID`, which the server stores against every session at open
time. Downstream drains are filtered by ownership, and each client has
its own wake channel. Without this, whichever client's HTTP request
reaches `drainAll` first would receive every other client's frames and
silently drop them, breaking every concurrent TLS stream.

### Active vs idle drain windows

[`internal/exit/exit.go`](internal/exit/exit.go) — `drainWindow`.
A POST that carried real work (SYN, data, FIN, RST) uses the short
`ActiveDrainWindow` (350 ms): the client worker is blocked waiting,
and stalling it on the 8 s long-poll budget creates head-of-line
blocking when many sessions are queueing SYNs. Empty (idle) polls keep
the full `LongPollWindow` (8 s) because their whole purpose is to wait
for downstream pushes.

### Transactional drain with rollback

[`internal/session/session.go`](internal/session/session.go) —
`DrainTxLimitedTxn` / `RollbackDrain`. The drain returns both the
frames and a snapshot of the pre-drain session state. If the batch
carrying those frames can't be sent (transport error, decode failure,
Apps Script error page), the carrier passes the snapshot to
`RollbackDrain` and the SYN/payload is restored intact. Any new bytes
queued during the in-flight window are preserved — they get appended
after the restored ones, in original arrival order.

### Connect-data optimization (SYN ride-along)

[`internal/session/session.go`](internal/session/session.go) —
`EnqueueInitialData`. The first SOCKS write for a new session rides on
the SYN frame's payload instead of waiting for a separate data frame.
For TLS this saves one round-trip per handshake.

The comment on `EnqueueInitialData` documents a real bug this design
caused: an earlier version *prepended* data on each call, assuming it
would only be called once. The SOCKS adapter actually calls it on
every write, and prepending reverses byte order — silently corrupting
TLS records and inflating every upload-throughput benchmark by ~5×.

### IPv4/IPv6 listen-network detection

[`internal/socks/server.go`](internal/socks/server.go) —
`listenNetwork`. Go's default `net.Listen("tcp", ...)` binds an
AF_INET6 socket with V4MAPPED, which is invisible until you run on a
Linux host with `net.ipv6.bindv6only=1`. There, the same code refuses
IPv4 connections. The fix detects IP literals and forces "tcp4"/"tcp6"
explicitly; hostnames keep "tcp" so resolver-driven setups still work.

### TCP_NODELAY + TCP_QUICKACK

[`internal/socks/server.go`](internal/socks/server.go) and
[`internal/exit/exit.go`](internal/exit/exit.go). Both ends of every
TCP connection have Nagle and (on Linux) delayed-ACK disabled.
Together they avoid two independent ~40 ms kernel stalls on small
request/reply pairs — TLS handshake records, DNS-over-HTTPS, REST
GETs. Without this, every interactive request pays up to 80 ms of
pure kernel latency.

### DNS-on-server, no client leaks

[`internal/socks/server.go`](internal/socks/server.go) registers a
no-op resolver, so any SOCKS5 client that uses `socks5h://` sends the
hostname through the tunnel as a string and the VPS resolves it. The
local machine never does DNS for tunneled traffic.

---

## Where to start reading

Roughly in dependency order:

1. **[internal/protocol/protocol.go](internal/protocol/protocol.go)** —
   55 lines. The wire-level constants and the version-probe types.
   Read this first to know the contract.
2. **[internal/frame/frame.go](internal/frame/frame.go)** — the frame
   layout and Marshal/Unmarshal. ~125 lines.
3. **[internal/frame/crypto.go](internal/frame/crypto.go)** — the
   batch envelope: zstd + AES-GCM + base64. ~310 lines, with a
   wire-format diagram in the comments.
4. **[internal/session/session.go](internal/session/session.go)** —
   per-connection state machine. The most important file in the repo
   for understanding the data flow. ~550 lines.
5. **[internal/carrier/client.go](internal/carrier/client.go)** — the
   client-side poll loop. Read `pollOnce` and `drainAll` first; the
   blacklist/picker code lives in `endpoints.go`.
6. **[internal/exit/exit.go](internal/exit/exit.go)** — the server-side
   handler. Read `handleTunnel`, `routeIncoming`, `openSession`, and
   `drainAll` in that order.

The two `_test.go` files worth a look:
[internal/frame/frame_test.go](internal/frame/frame_test.go) (round-trip
properties of the wire format) and
[internal/session/session_test.go](internal/session/session_test.go)
(transactional drain / rollback behaviour).

---

## A note on duplication that was kept

[`humanBytes`](internal/carrier/stats.go) is defined identically in
both `internal/carrier/stats.go` and `internal/exit/stats.go`. The
comment on the exit copy justifies the choice: rather than introduce
an inter-package dependency for one 13-line helper, the duplication
is left in place. This is a deliberate trade-off — calling it out in
code review and choosing to keep it is a valid engineering decision,
and one I'd make again.
