package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

const (
	// pollIdleSleep is the breather between polls when nothing is happening.
	// 10ms instead of 50ms: keeps workers responsive to kick() misses and
	// idle-slot retry at negligible CPU cost at true idle. Adaptive backoff
	// (see idleBackoff) extends this when consecutive polls return no work.
	pollIdleSleep = 10 * time.Millisecond

	// pureDownloadIdleCap is referenced by sanity assertions in the
	// idle-poll tests. The runtime cap is bucketCount × idleSlotsPerBucket,
	// applied inside pickRelayEndpoint; this constant is the floor a single
	// endpoint should provide via implicit per-URL bucketing (unlabeled
	// endpoints each get their own bucket, so 1 endpoint = 1 bucket = at
	// least 1 slot; the test asserts ≥ this floor as a smoke check).
	pureDownloadIdleCap = 2

	// pollTimeout is the per-request HTTP ceiling; should comfortably exceed
	// the server's long-poll window (~25s).
	pollTimeout = 120 * time.Second

	// Hard cap for one relay response body to avoid spending CPU/memory on
	// unexpectedly huge non-frame payloads (HTML error pages, quota pages, etc).
	maxRelayResponseBodyBytes = 32 * 1024 * 1024
)

func readRelayResponseBody(r io.Reader, contentLength int64, limit int) ([]byte, error) {
	if contentLength > int64(limit) {
		return nil, fmt.Errorf("relay response too large (%d bytes > %d)", contentLength, limit)
	}
	if contentLength >= 0 {
		body := make([]byte, int(contentLength))
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		return body, nil
	}
	lr := &io.LimitedReader{R: r, N: int64(limit) + 1}
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, fmt.Errorf("relay response too large (%d bytes > %d)", len(body), limit)
	}
	return body, nil
}

// Config bundles everything the carrier needs to talk to the relay.
type Config struct {
	ScriptURLs    []string // one or more full https://script.google.com/macros/s/.../exec URLs
	ClientVersion string   // build version string for diagnostics

	// ScriptAccounts is an optional parallel slice to ScriptURLs labeling each
	// deployment with the Google account it lives under. When set, the periodic
	// stats line aggregates today/script counts by account so the operator can
	// see how much of each account's ~20k/day quota has been spent. nil or
	// shorter slices are tolerated; missing entries are treated as unlabeled.
	ScriptAccounts []string

	Fronting    FrontingConfig
	AESKeyHex   string // 64-char hex, must match server
	DebugTiming bool   // when true, log per-session TTFB and per-poll Apps Script RTT

	// CoalesceStep / CoalesceMax enable adaptive uplink coalescing on kick().
	// When CoalesceStep > 0 the first kick of a burst arms a step timer; each
	// subsequent kick within the window resets it, bounded by CoalesceMax from
	// the first kick. Bursts collapse into a single wake. Both 0 = disabled.
	CoalesceStep time.Duration
	CoalesceMax  time.Duration

	// IdleSlotsPerBucket is the number of concurrent idle long-polls allowed
	// per account bucket. <= 0 means default (2). Validated and capped at 3
	// by the config layer; the carrier accepts any positive value here but
	// users should configure through the config layer to get the cap and the
	// "why this cap" error message.
	IdleSlotsPerBucket int
}

// waker is a broadcast notifier: Broadcast() wakes all goroutines currently
// blocked on C() simultaneously, unlike a buffered chan which only wakes one.
type waker struct {
	mu sync.Mutex
	ch chan struct{}
}

func newWaker() *waker { return &waker{ch: make(chan struct{})} }

// C returns the current channel to select on. Must be captured before
// entering select so a concurrent Broadcast() cannot be missed.
func (w *waker) C() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ch
}

// Broadcast unblocks all goroutines currently waiting on C().
func (w *waker) Broadcast() {
	w.mu.Lock()
	defer w.mu.Unlock()
	close(w.ch)
	w.ch = make(chan struct{})
}

// Client owns the session map and the long-poll loop.
type Client struct {
	cfg                Config
	aead               *frame.Crypto
	httpClients        []*http.Client // one per SNI host; round-robined per request
	nextHTTP           atomic.Uint64  // round-robin index into httpClients
	debugTiming        bool
	numWorkers         int // workersPerEndpoint × len(endpoints); semaphore caps actual in-flight
	bucketCount        int // distinct in-flight buckets; one per labeled account, plus one per unlabeled endpoint
	idleSlotsPerBucket int // resolved from Config.IdleSlotsPerBucket; max concurrent polls per bucket
	clientVersion      string

	// clientID is a random 16-byte identifier minted once per process. It is
	// embedded in every encrypted batch so the server can route downstream
	// frames back to the correct client when several clients share one server.
	clientID [frame.ClientIDLen]byte

	// debugStarts tracks session start times when debugTiming is on so we can
	// log time-to-first-byte once each session receives its first downstream
	// frame. Entries are deleted on first rx.
	debugStarts sync.Map

	mu       sync.Mutex
	sessions map[[frame.SessionIDLen]byte]*session.Session
	inFlight map[[frame.SessionIDLen]byte]bool
	txReady  map[[frame.SessionIDLen]byte]struct{} // sessions with pending TX frames

	// endpointMu protects endpoints (per-endpoint state), nextEndpoint
	// (picker round-robin cursor), and inFlightByBucket (per-account
	// in-flight semaphore counters). Single mutex because pickRelayEndpoint
	// needs to atomically (a) find an eligible endpoint and (b) reserve a
	// semaphore slot.
	endpointMu       sync.Mutex
	endpoints        []relayEndpoint
	nextEndpoint     int
	inFlightByBucket map[string]int // bucket key → current in-flight poll count

	wake  *waker // broadcasts to all idle poll goroutines simultaneously
	stats clientStats

	// Adaptive kick coalescing (see Config.CoalesceStep/Max). When step <= 0
	// these fields are unused and kick() broadcasts immediately.
	coalesceStep     time.Duration
	coalesceMax      time.Duration
	coalesceMu       sync.Mutex
	coalesceTimer    *time.Timer // armed during a coalesce window; nil otherwise
	coalesceDeadline time.Time   // hard cap for the in-flight window

	recoveryProbeAddr string
}

// clientStats holds atomic counters surfaced periodically by statsLoop.
// All fields are uint64 so they can be Load()ed without locking.
type clientStats struct {
	framesOut     atomic.Uint64
	framesIn      atomic.Uint64
	bytesOut      atomic.Uint64
	bytesIn       atomic.Uint64
	pollsOK       atomic.Uint64
	pollsFail     atomic.Uint64
	rstFromServer atomic.Uint64
	sessionsOpen  atomic.Uint64
	sessionsClose atomic.Uint64
}

// New constructs a Client. The HTTP client is preconfigured for domain
// fronting per cfg.Fronting.
func New(cfg Config) (*Client, error) {
	aead, err := frame.NewCryptoFromHexKey(cfg.AESKeyHex)
	if err != nil {
		return nil, err
	}

	endpoints := make([]relayEndpoint, 0, len(cfg.ScriptURLs))
	seen := make(map[string]struct{}, len(cfg.ScriptURLs))
	for i, raw := range cfg.ScriptURLs {
		url := strings.TrimSpace(raw)
		if url == "" {
			continue
		}
		if _, ok := seen[url]; ok {
			continue
		}
		seen[url] = struct{}{}
		account := ""
		if i < len(cfg.ScriptAccounts) {
			account = strings.TrimSpace(cfg.ScriptAccounts[i])
		}
		ep := relayEndpoint{url: url, account: account}
		if account != "" {
			ep.bucket = "acct:" + account
		} else {
			ep.bucket = "url:" + url
		}
		endpoints = append(endpoints, ep)
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("at least one script URL is required")
	}

	// Each Google account is one in-flight bucket. Endpoints without an
	// account label each get their own bucket (Apps Script throttles per
	// account; we can't tell unlabeled deployments apart, so we conservatively
	// assume they're all distinct — which matches v1.5 behavior where each
	// endpoint was independently rate-managed). The in-flight semaphore on
	// each bucket caps concurrent polls hitting that account, preserving the
	// per-account anti-abuse protection that motivated v1.6's bucketing
	// (issue #56) without partitioning the worker pool itself.
	bucketSeen := make(map[string]struct{}, len(endpoints))
	labeled := 0
	for _, ep := range endpoints {
		bucketSeen[ep.bucket] = struct{}{}
		if ep.account != "" {
			labeled++
		}
	}
	bucketCount := len(bucketSeen)

	var clientID [frame.ClientIDLen]byte
	if _, err := rand.Read(clientID[:]); err != nil {
		// crypto/rand failure is unrecoverable; fail fast rather than emitting
		// an all-zero ID that would collide with every other unupgraded client.
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}

	idleSlotsPerBucket := cfg.IdleSlotsPerBucket
	if idleSlotsPerBucket <= 0 {
		idleSlotsPerBucket = 2
	}
	// Single-bucket configs (one endpoint or one labeled account) need at
	// least pureDownloadIdleCap idle slots so the gap during pollIdleSleep
	// re-entry doesn't stall pure-download throughput (one slot is held by
	// the active long-poll; the other rotates in as that one returns).
	// Multi-bucket configs already have multiple concurrent slots across
	// buckets, so the per-bucket floor only matters when bucketCount=1.
	if bucketCount == 1 && idleSlotsPerBucket < pureDownloadIdleCap {
		idleSlotsPerBucket = pureDownloadIdleCap
	}
	// Worker count scales with endpoint count (v1.5 behavior). v1.6's
	// bucket-scaled worker pool starved the picker on the common case of
	// multiple deployments under one account or unlabeled configs —
	// issue #113 (slower than v1.5 despite "more workers") and the
	// implicit regression for legacy configs (5 unlabeled endpoints gave
	// only 4 workers vs v1.5's 15). The per-bucket idle-slot semaphore
	// (pickIdleEndpoint) still caps simultaneous standing polls per
	// account so issue #56 stays fixed; active polls bypass that cap
	// because they terminate quickly with TX delivery.
	numWorkers := workersPerEndpoint * len(endpoints)
	if labeled > 0 || len(endpoints) == 1 {
		log.Printf("[carrier] %d worker(s) across %d bucket(s) (%d endpoint(s)), %d idle slot(s)/bucket",
			numWorkers, bucketCount, len(endpoints), idleSlotsPerBucket)
	} else {
		log.Printf("[carrier] %d worker(s) across %d endpoint(s) (no account labels — each endpoint is its own bucket), %d idle slot(s)/endpoint",
			numWorkers, len(endpoints), idleSlotsPerBucket)
	}

	return &Client{
		cfg:                cfg,
		aead:               aead,
		httpClients:        NewFrontedClients(cfg.Fronting, pollTimeout, endpoints[0].url),
		debugTiming:        cfg.DebugTiming,
		numWorkers:         numWorkers,
		bucketCount:        bucketCount,
		idleSlotsPerBucket: idleSlotsPerBucket,
		clientVersion:      cfg.ClientVersion,
		clientID:           clientID,
		sessions:           make(map[[frame.SessionIDLen]byte]*session.Session),
		inFlight:           make(map[[frame.SessionIDLen]byte]bool),
		txReady:            make(map[[frame.SessionIDLen]byte]struct{}),
		endpoints:          endpoints,
		inFlightByBucket:   make(map[string]int, bucketCount),
		wake:               newWaker(),
		coalesceStep:       cfg.CoalesceStep,
		coalesceMax:        cfg.CoalesceMax,
		recoveryProbeAddr:  recoveryProbeAddress(cfg),
	}, nil
}

// NewSession creates a tunneled session for target ("host:port") and registers
// it with the long-poll loop. Returns the session for the caller (typically
// the SOCKS adapter) to wrap in a VirtualConn.
func (c *Client) NewSession(target string) *session.Session {
	var id [frame.SessionIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		// crypto/rand failure is unrecoverable; panic so the process exits
		// rather than emitting an all-zero ID.
		panic(fmt.Errorf("crypto/rand: %w", err))
	}
	s := session.New(id, target, true)
	s.OnTx = func() {
		c.mu.Lock()
		c.txReady[id] = struct{}{}
		c.mu.Unlock()
		c.kick()
	}
	c.mu.Lock()
	c.sessions[id] = s
	c.txReady[id] = struct{}{} // SYN is pending immediately on creation
	c.mu.Unlock()
	c.stats.sessionsOpen.Add(1)
	if c.debugTiming {
		c.debugStarts.Store(id, time.Now())
	}
	c.kick()
	return s
}

// Shutdown sends an RST frame for every active session so the server can
// release the corresponding upstream connections immediately rather than
// waiting for its idle-session GC. Intended to be called from a SIGINT/SIGTERM
// handler before canceling the main context. ctx bounds how long we'll wait
// for the final POST to complete.
//
// Best-effort: if the POST fails (network gone, server unreachable) we just
// return — the server's idle GC is the safety net for that case.
func (c *Client) Shutdown(ctx context.Context) {
	c.mu.Lock()
	if len(c.sessions) == 0 {
		c.mu.Unlock()
		return
	}
	rsts := make([]*frame.Frame, 0, len(c.sessions))
	for id := range c.sessions {
		rsts = append(rsts, &frame.Frame{
			SessionID: id,
			Flags:     frame.FlagRST,
		})
	}
	c.mu.Unlock()

	body, err := frame.EncodeBatch(c.aead, c.clientID, rsts)
	if err != nil {
		log.Printf("[carrier] shutdown: encode failed: %v", err)
		return
	}

	_, scriptURL := c.pickRelayEndpoint()
	if scriptURL == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, scriptURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "text/plain")

	log.Printf("[carrier] shutdown: sending RST for %d active sessions", len(rsts))
	resp, err := c.pickHTTPClient().Do(req)
	if err != nil {
		log.Printf("[carrier] shutdown: send failed (server idle GC will clean up): %v", err)
		return
	}
	_ = resp.Body.Close()
}

// Run spawns c.numWorkers concurrent poll goroutines and blocks until ctx is
// canceled. Worker count scales with the number of configured endpoints so that
// adding more script URLs increases parallelism rather than spreading the same
// fixed pool thinner.
func (c *Client) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for i := 0; i < c.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runWorker(ctx)
		}()
	}
	// Periodic stats line so an operator can spot trends without grepping.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runStatsLoop(ctx)
	}()
	// Hourly fetch of each deployment's self-reported invocation count.
	// Logged in the next [stats] line as `script=N` next to the existing
	// client-side `today=N` so the user sees both perspectives.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runScriptStatsLoop(ctx)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runEndpointRecoveryLoop(ctx)
	}()
	wg.Wait()
	return ctx.Err()
}

func (c *Client) runWorker(ctx context.Context) {
	consecutiveIdle := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		didWork := c.pollOnce(ctx)
		c.gcDoneSessions()
		if didWork {
			consecutiveIdle = 0
			continue
		}
		consecutiveIdle++
		// Capture the wake channel before entering select so we cannot
		// miss a Broadcast() that fires between drainAll() returning
		// empty and us entering the wait. The wake takes precedence over
		// the timer, so backoff never delays the response to new TX.
		wakeCh := c.wake.C()
		select {
		case <-ctx.Done():
			return
		case <-wakeCh:
			consecutiveIdle = 0
		case <-time.After(idleBackoff(consecutiveIdle)):
		}
	}
}

// idleBackoff returns how long a worker should sleep after n consecutive
// no-work polls. The wake channel is selected against this timer so any
// new TX (kick) cancels the sleep immediately and any held server-side
// long-poll receives downstream chunks without needing a fresh poll —
// so even a 1s tail does not add user-visible latency.
func idleBackoff(n int) time.Duration {
	switch {
	case n < 3:
		return pollIdleSleep
	case n < 10:
		return 50 * time.Millisecond
	case n < 30:
		return 250 * time.Millisecond
	default:
		return time.Second
	}
}

// pollOnce drains pending tx frames, POSTs them as a batch, and routes any
// response frames back to their sessions. Returns true if any work was done
// (frames sent or received) so the Run loop can decide whether to sleep.
func (c *Client) pollOnce(ctx context.Context) bool {
	frames, drainedIDs, snaps := c.drainAll()
	if len(drainedIDs) > 0 {
		defer c.releaseInFlight(drainedIDs)
	}
	// rollbackPending: set to false on success paths (batch delivered to the
	// exit server, response received) so snapshots are discarded. Stays true
	// on every other return path so unsent frames are restored to their
	// sessions and resent on the next poll cycle.
	rollbackPending := len(snaps) > 0
	defer func() {
		if rollbackPending {
			c.rollbackDrained(snaps)
		}
	}()
	// Idle long-polls (no TX) are subject to the per-bucket idle slot cap so
	// each Google account holds at most idleSlotsPerBucket simultaneous
	// standing polls — Apps Script anti-abuse fires when one account sees
	// too many concurrent UrlFetchApp invocations (issue #56). Active polls
	// (TX present) bypass the cap because they terminate quickly with the
	// drained batch; this matches v1.5 behavior. The reservation is tracked
	// across the attempt loop so same-poll failovers don't hold two slots.
	isIdlePoll := len(frames) == 0
	pickedIdleIdx := -1
	defer func() {
		c.releaseBucketSlot(pickedIdleIdx)
	}()

	// Stats: classify poll outcome on return so callers don't have to remember
	// to bump counters at every terminal point inside the retry loop.
	var (
		attempted bool
		pollOK    bool
	)
	defer func() {
		if !attempted {
			return
		}
		if pollOK {
			c.stats.pollsOK.Add(1)
		} else {
			c.stats.pollsFail.Add(1)
		}
	}()

	body, err := frame.EncodeBatch(c.aead, c.clientID, frames)
	if err != nil {
		log.Printf("[carrier] failed to prepare encrypted request batch: %v", err)
		return false
	}

	maxAttempts := 1
	if len(c.endpoints) > 1 {
		// One same-poll failover attempt keeps drained TX payload from being lost
		// when one deployment intermittently fails under quota pressure.
		maxAttempts = 2
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// On retry, release the previous attempt's idle slot (if held) so
		// a same-poll failover doesn't hold two slots simultaneously.
		if pickedIdleIdx >= 0 {
			c.releaseBucketSlot(pickedIdleIdx)
			pickedIdleIdx = -1
		}
		var endpointIdx int
		var scriptURL string
		if isIdlePoll {
			endpointIdx, scriptURL = c.pickIdleEndpoint()
		} else {
			endpointIdx, scriptURL = c.pickRelayEndpoint()
		}
		if endpointIdx < 0 || scriptURL == "" {
			c.endpointMu.Lock()
			anyConfigured := len(c.endpoints) > 0
			c.endpointMu.Unlock()
			if !anyConfigured {
				log.Printf("[carrier] no relay script URLs are configured")
			}
			// Otherwise: either all endpoints are blacklisted, or (idle
			// path only) every non-blacklisted bucket is already at its
			// idle cap. Per-endpoint blacklist logs were emitted at the
			// failing transitions; cap pressure is normal under high
			// concurrent download load. The worker idle-backs off.
			return false
		}
		if isIdlePoll {
			pickedIdleIdx = endpointIdx
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, scriptURL, bytes.NewReader(body))
		if err != nil {
			log.Printf("[carrier] failed to build relay request: %v", err)
			return false
		}
		req.Header.Set("Content-Type", "text/plain")
		attempted = true

		var pollStart time.Time
		if c.debugTiming {
			pollStart = time.Now()
		}
		resp, err := c.pickHTTPClient().Do(req)
		if err == nil {
			// Apps Script counts every doPost invocation, regardless of status,
			// so bump the daily counter once we know the request reached it.
			c.bumpDailyCount(endpointIdx)
		}
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			if isLocalNetworkOffline(err) {
				c.markEndpointLocalNetworkFailure(endpointIdx)
			} else {
				c.markEndpointFailure(endpointIdx)
			}
			if attempt < maxAttempts {
				log.Printf("[carrier] relay request failed via %s (attempt %d/%d): %v; retrying alternate script", ShortScriptKey(scriptURL), attempt, maxAttempts, err)
				continue
			}
			log.Printf("[carrier] relay request failed via %s: %v (check internet access, script_keys, and google_host)", ShortScriptKey(scriptURL), err)
			time.Sleep(time.Second) // back off on transport errors
			return false
		}

		respBody, readErr := readRelayResponseBody(resp.Body, resp.ContentLength, maxRelayResponseBodyBytes)
		_ = resp.Body.Close()
		if readErr != nil {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] failed to read relay response via %s (attempt %d/%d): %v; retrying alternate script", ShortScriptKey(scriptURL), attempt, maxAttempts, readErr)
				continue
			}
			log.Printf("[carrier] failed to read relay response: %v", readErr)
			return false
		}

		if resp.StatusCode == http.StatusNoContent || len(respBody) == 0 {
			c.markEndpointSuccess(endpointIdx)
			pollOK = true
			rollbackPending = false // batch delivered; server returned no body
			countFrameBytes(&c.stats.framesOut, &c.stats.bytesOut, frames)
			return len(frames) > 0
		}
		if resp.StatusCode != http.StatusOK {
			switch resp.StatusCode {
			case http.StatusForbidden: // 403
				c.markEndpoint403(endpointIdx)
				if attempt < maxAttempts {
					log.Printf("[carrier] relay returned HTTP 403 via %s (attempt %d/%d); retrying alternate script", ShortScriptKey(scriptURL), attempt, maxAttempts)
					continue
				}
				log.Printf("[carrier] relay returned HTTP 403 via %s (Apps Script quota exhausted or deployment not set to 'Anyone'; quota resets at midnight Pacific — consider adding more script deployments or waiting for reset)", ShortScriptKey(scriptURL))
			case http.StatusTooManyRequests: // 429
				c.markEndpoint429(endpointIdx)
				if attempt < maxAttempts {
					log.Printf("[carrier] relay returned HTTP 429 (rate-limited) via %s (attempt %d/%d); retrying alternate script", ShortScriptKey(scriptURL), attempt, maxAttempts)
					continue
				}
				log.Printf("[carrier] relay returned HTTP 429 (rate-limited) via %s; backing off and will retry automatically", ShortScriptKey(scriptURL))
			default:
				c.markEndpointFailure(endpointIdx)
				if attempt < maxAttempts {
					log.Printf("[carrier] relay returned HTTP %d via %s (attempt %d/%d); retrying alternate script", resp.StatusCode, ShortScriptKey(scriptURL), attempt, maxAttempts)
					continue
				}
				log.Printf("[carrier] relay returned HTTP %d via %s (verify Apps Script deployment is live and access is set to Anyone)", resp.StatusCode, ShortScriptKey(scriptURL))
			}
			return false
		}
		if len(respBody) > maxRelayResponseBodyBytes {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response too large via %s (attempt %d/%d); retrying alternate script", ShortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay response too large via %s (%d bytes > %d); dropping batch to protect stability", ShortScriptKey(scriptURL), len(respBody), maxRelayResponseBodyBytes)
			rollbackPending = false // request reached the server; we just can't ingest the response
			return len(frames) > 0
		}
		if isLikelyNonBatchRelayPayload(respBody) {
			errReason, errHard := classifyRelayErrorBody(respBody)
			if errHard {
				c.markEndpointHardFailure(endpointIdx)
			} else {
				c.markEndpointFailure(endpointIdx)
			}
			if attempt < maxAttempts {
				log.Printf("[carrier] relay returned non-batch payload via %s (attempt %d/%d); retrying alternate script", ShortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			if errReason != "" {
				log.Printf("[carrier] relay returned non-batch payload via %s: %s", ShortScriptKey(scriptURL), errReason)
			} else {
				log.Printf("[carrier] relay returned non-batch payload via %s (likely HTML/JSON error page), dropping response", ShortScriptKey(scriptURL))
			}
			return len(frames) > 0
		}

		_, rxFrames, decodeErr := frame.DecodeBatch(c.aead, respBody)
		if decodeErr != nil {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response was invalid via %s (attempt %d/%d): %v; retrying alternate script", ShortScriptKey(scriptURL), attempt, maxAttempts, decodeErr)
				continue
			}
			log.Printf("[carrier] relay response was invalid via %s (possibly HTML/error page instead of encrypted data): %v", ShortScriptKey(scriptURL), decodeErr)
			rollbackPending = false // Apps Script returned a normal-looking 200; the exit server most likely processed the batch even though we can't ingest the response
			return len(frames) > 0
		}

		for _, f := range rxFrames {
			c.routeRx(f)
		}
		c.markEndpointSuccess(endpointIdx)
		pollOK = true
		rollbackPending = false // batch delivered, response decoded
		countFrameBytes(&c.stats.framesOut, &c.stats.bytesOut, frames)
		countFrameBytes(&c.stats.framesIn, &c.stats.bytesIn, rxFrames)
		if c.debugTiming {
			log.Printf("[timing] poll rtt=%dms tx_frames=%d rx_frames=%d resp_bytes=%d via %s",
				time.Since(pollStart).Milliseconds(), len(frames), len(rxFrames), len(respBody), ShortScriptKey(scriptURL))
		}
		return len(frames) > 0 || len(rxFrames) > 0
	}

	return false
}

// countFrameBytes adds the count and total payload size of frames to two
// atomic counters. Centralised so the call sites in pollOnce stay terse.
func countFrameBytes(frameCounter, byteCounter *atomic.Uint64, frames []*frame.Frame) {
	if len(frames) == 0 {
		return
	}
	var bytes uint64
	for _, f := range frames {
		bytes += uint64(len(f.Payload))
	}
	frameCounter.Add(uint64(len(frames)))
	byteCounter.Add(bytes)
}

// pickHTTPClient returns the next HTTP client in round-robin order. Each
// client has a distinct SNI host and connection pool, so successive calls
// naturally spread requests across separate throttle buckets.
func (c *Client) pickHTTPClient() *http.Client {
	if len(c.httpClients) == 1 {
		return c.httpClients[0]
	}
	idx := c.nextHTTP.Add(1) - 1
	return c.httpClients[idx%uint64(len(c.httpClients))]
}

func (c *Client) drainAll() ([]*frame.Frame, [][frame.SessionIDLen]byte, map[[frame.SessionIDLen]byte]*session.DrainSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*frame.Frame
	var drainedIDs [][frame.SessionIDLen]byte
	snaps := map[[frame.SessionIDLen]byte]*session.DrainSnapshot{}
	batchCap := protocol.MaxDrainFramesPerBatch
	if len(c.sessions) >= protocol.BusySessionThreshold {
		batchCap = protocol.MaxDrainFramesPerBatchBusy
	}
	remaining := batchCap

	// Snapshot and sort active sessions by queue age to ensure fairness.
	type sessionRef struct {
		id       [frame.SessionIDLen]byte
		queuedAt time.Time
	}
	refs := make([]sessionRef, 0, len(c.txReady))
	for id := range c.txReady {
		if s, ok := c.sessions[id]; ok {
			refs = append(refs, sessionRef{id: id, queuedAt: s.FirstQueuedAt()})
		} else {
			delete(c.txReady, id)
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].queuedAt.Before(refs[j].queuedAt)
	})

	drain := func(id [frame.SessionIDLen]byte, synOnly bool) {
		if remaining <= 0 {
			return
		}
		s, ok := c.sessions[id]
		if !ok {
			delete(c.txReady, id)
			return
		}
		if c.inFlight[id] {
			return // already sending; releaseInFlight will re-add if needed
		}
		if synOnly && !s.HasPendingSYN() {
			return
		}
		perSessionCap := protocol.MaxDrainFramesPerSession
		if remaining < perSessionCap {
			perSessionCap = remaining
		}
		frames, snap := s.DrainTxLimitedTxn(protocol.MaxFramePayload, perSessionCap)
		delete(c.txReady, id) // remove now; OnTx re-adds if more data arrives
		if len(frames) == 0 {
			return
		}
		c.inFlight[id] = true
		drainedIDs = append(drainedIDs, id)
		if snap != nil {
			snaps[id] = snap
		}
		out = append(out, frames...)
		remaining -= len(frames)
	}

	// First pass: SYN sessions only. New connections claim batch slots before
	// ongoing data transfers so a large upload/download cannot push SYN frames
	// out of the batch and delay connection setup by a full poll cycle.
	for _, r := range refs {
		drain(r.id, true)
	}
	// Second pass: remaining data sessions.
	for _, r := range refs {
		drain(r.id, false)
	}
	return out, drainedIDs, snaps
}

// rollbackDrained restores every session named in snaps to its pre-drain
// state. Used on failure paths where the batch never reached the exit server
// (transport error, Apps Script rejection, etc.) so the SYN/payload can be
// retransmitted on the next poll instead of being silently lost.
func (c *Client) rollbackDrained(snaps map[[frame.SessionIDLen]byte]*session.DrainSnapshot) {
	if len(snaps) == 0 {
		return
	}
	c.mu.Lock()
	type pending struct {
		s    *session.Session
		snap *session.DrainSnapshot
	}
	out := make([]pending, 0, len(snaps))
	for id, snap := range snaps {
		if s, ok := c.sessions[id]; ok {
			out = append(out, pending{s: s, snap: snap})
		}
	}
	c.mu.Unlock()
	for _, p := range out {
		p.s.RollbackDrain(p.snap)
	}
}

func (c *Client) releaseInFlight(ids [][frame.SessionIDLen]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range ids {
		delete(c.inFlight, id)
		// Re-add to txReady if the batch cap left data behind or new data
		// arrived while this session was in-flight.
		if s, ok := c.sessions[id]; ok && s.HasPendingTx() {
			c.txReady[id] = struct{}{}
		}
	}
}

func (c *Client) routeRx(f *frame.Frame) {
	c.mu.Lock()
	s, ok := c.sessions[f.SessionID]
	c.mu.Unlock()
	if !ok {
		return // unknown session - drop
	}
	if c.debugTiming && len(f.Payload) > 0 {
		// First downstream frame for a session implies time-to-first-byte.
		// LoadAndDelete ensures we log this exactly once per session.
		if start, loaded := c.debugStarts.LoadAndDelete(f.SessionID); loaded {
			ttfb := time.Since(start.(time.Time))
			log.Printf("[timing] %x ttfb=%dms target=%s",
				f.SessionID[:4], ttfb.Milliseconds(), s.Target)
		}
	}
	if f.HasFlag(frame.FlagRST) {
		// Server has no state for this session (e.g. it restarted). Tear it down
		// immediately so the SOCKS client gets an error and reconnects cleanly.
		log.Printf("[carrier] RST from server for session %x; closing", f.SessionID[:4])
		s.CloseRx()
		s.RequestClose()
		c.mu.Lock()
		delete(c.sessions, f.SessionID)
		delete(c.txReady, f.SessionID)
		c.mu.Unlock()
		if c.debugTiming {
			c.debugStarts.Delete(f.SessionID)
		}
		s.Stop()
		c.stats.rstFromServer.Add(1)
		c.stats.sessionsClose.Add(1)
		return
	}
	s.ProcessRx(f)
}

func (c *Client) gcDoneSessions() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, s := range c.sessions {
		if s.IsDone() {
			s.Stop()
			delete(c.sessions, id)
			delete(c.txReady, id)
			if c.debugTiming {
				c.debugStarts.Delete(id)
			}
			c.stats.sessionsClose.Add(1)
		}
	}
}

// kick broadcasts to all idle poll workers. Safe to call from any goroutine.
//
// When adaptive coalescing is enabled (coalesceStep > 0) kicks within a
// burst are collapsed into a single delayed wake: the first kick arms a
// step-ms timer and records a hard deadline (now + coalesceMax); subsequent
// kicks reset the step timer (capped at the hard deadline) so a steady
// stream of arrivals does not delay the wake past coalesceMax. When step
// is 0 the wake fires immediately as before.
func (c *Client) kick() {
	if c.coalesceStep <= 0 {
		c.wake.Broadcast()
		return
	}

	c.coalesceMu.Lock()
	defer c.coalesceMu.Unlock()

	now := time.Now()
	if c.coalesceTimer == nil {
		// First kick of a burst: set hard deadline and arm the step timer.
		c.coalesceDeadline = now.Add(c.coalesceMax)
		c.coalesceTimer = time.AfterFunc(c.coalesceStep, c.fireCoalesceWake)
		return
	}

	// Subsequent kick: extend the step timer, but never past the hard cap.
	nextFire := now.Add(c.coalesceStep)
	if nextFire.After(c.coalesceDeadline) {
		nextFire = c.coalesceDeadline
	}
	wait := nextFire.Sub(now)
	if wait <= 0 {
		// Already at or past the hard deadline — let the existing timer fire.
		return
	}
	c.coalesceTimer.Reset(wait)
}

// fireCoalesceWake clears the timer and broadcasts the wake. Called from
// the time.AfterFunc goroutine when the coalesce window closes.
func (c *Client) fireCoalesceWake() {
	c.coalesceMu.Lock()
	c.coalesceTimer = nil
	c.coalesceMu.Unlock()
	c.wake.Broadcast()
}
