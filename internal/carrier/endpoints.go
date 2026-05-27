package carrier

import (
	"log"
	"strings"
	"time"
)

const (
	// Endpoint failure backoff to shed unhealthy deployments during quota spikes
	// or tail-latency events without changing protocol behavior.
	endpointBlacklistBaseTTL = 3 * time.Second
	endpointBlacklistMaxTTL  = 1 * time.Hour

	// workersPerEndpoint is the number of concurrent poll goroutines spawned for
	// each configured script URL. Total workers = workersPerEndpoint × len(endpoints).
	// Scaling with endpoint count means adding more deployment IDs increases
	// parallelism rather than just spreading the same fixed pool thinner.
	workersPerEndpoint = 3
)

type relayEndpoint struct {
	url                 string
	account             string // optional human-readable Google account label, "" = unlabeled
	blacklistedTill     time.Time
	localNetworkOffline bool
	failCount           int
	statsOK             uint64
	statsFail           uint64

	// bucket is the key into Client.inFlightByBucket. For labeled endpoints
	// it is "acct:"+account so all deployments under one Google account share
	// a single in-flight semaphore (Apps Script throttles per-account). For
	// unlabeled endpoints it is "url:"+url so each deployment gets its own
	// implicit semaphore — that matches v1.5 behavior where each endpoint
	// was independently rate-managed.
	bucket string

	// Per-quota-window counters. dailyCount is the number of HTTP responses
	// received from Apps Script in the current window; dailyResetAt is the
	// next midnight Pacific (the boundary at which Apps Script resets the
	// per-account UrlFetch quota). Both are managed via touchDailyWindow.
	dailyCount   uint64
	dailyResetAt time.Time

	// Script-reported per-day invocation count, fetched hourly via doGet on
	// the same /exec URL. scriptCountAt is zero until the first successful
	// fetch; scriptStatsErrLogged suppresses repeat "needs redeploy" warnings
	// when the deployed Code.gs is the legacy version that doesn't return JSON.
	scriptCount          uint64
	scriptCountAt        time.Time
	scriptStatsErrLogged bool
}

// pickRelayEndpoint picks the next non-blacklisted endpoint in round-robin
// order. The per-bucket in-flight semaphore is enforced separately by
// acquireBucketSlot/releaseBucketSlot — only idle long-polls are gated by it
// (matches v1.5 behavior; active polls carrying TX terminate quickly with the
// drained payload and don't camp an account's concurrency budget).
func (c *Client) pickRelayEndpoint() (int, string) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	n := len(c.endpoints)
	if n == 0 {
		return -1, ""
	}
	now := time.Now()
	start := c.nextEndpoint % n
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		ep := &c.endpoints[idx]
		if ep.blacklistedTill.After(now) {
			continue
		}
		c.nextEndpoint = (idx + 1) % n
		return idx, ep.url
	}

	// Every endpoint is blacklisted. Refuse to send rather than hammer
	// flagged deployments (issues #121, #126). The worker will idle-backoff
	// until the soonest TTL elapses.
	return -1, ""
}

// pickIdleEndpoint is like pickRelayEndpoint but also requires the candidate
// endpoint's bucket to have an idle long-poll slot available, and reserves
// that slot atomically. Callers MUST pair a successful pick (idx >= 0) with
// releaseBucketSlot(idx). Returns -1 if every non-blacklisted endpoint's
// bucket is already at the per-bucket idle cap — the worker idle-backs off.
func (c *Client) pickIdleEndpoint() (int, string) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	n := len(c.endpoints)
	if n == 0 {
		return -1, ""
	}
	now := time.Now()
	start := c.nextEndpoint % n
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		ep := &c.endpoints[idx]
		if ep.blacklistedTill.After(now) {
			continue
		}
		if c.inFlightByBucket[ep.bucket] >= c.idleSlotsPerBucket {
			continue
		}
		c.inFlightByBucket[ep.bucket]++
		c.nextEndpoint = (idx + 1) % n
		return idx, ep.url
	}
	return -1, ""
}

// releaseBucketSlot frees the idle slot reserved by pickIdleEndpoint. Safe
// to call with idx < 0 (no-op).
func (c *Client) releaseBucketSlot(idx int) {
	if idx < 0 {
		return
	}
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if idx >= len(c.endpoints) {
		return
	}
	bucket := c.endpoints[idx].bucket
	if c.inFlightByBucket[bucket] > 0 {
		c.inFlightByBucket[bucket]--
	}
}

func (c *Client) markEndpointSuccess(endpointIdx int) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	wasFailing := ep.failCount > 0
	ep.statsOK++
	url := ep.url
	ep.failCount = 0
	ep.blacklistedTill = time.Time{}
	ep.localNetworkOffline = false
	c.endpointMu.Unlock()
	if wasFailing {
		log.Printf("[carrier] endpoint %s recovered (back in rotation)", ShortScriptKey(url))
	}
}

// markEndpointFailure applies the standard exponential backoff ramp (3 s → 1 h)
// for transient failures (network errors, 5xx, decode failures).
func (c *Client) markEndpointFailure(endpointIdx int) {
	c.markEndpointFailureWith(endpointIdx, 0)
}

// markEndpoint403 handles HTTP 403 (quota exhausted or deployment misconfigured).
// Quota walls don't self-heal in seconds; they persist until midnight Pacific.
// Jump straight to the 5-minute tier (failCount floor = 5 → next hit → 6 → 5 min)
// to avoid hammering a dead endpoint and wasting the failover slot on peers.
func (c *Client) markEndpoint403(endpointIdx int) {
	c.markEndpointFailureWith(endpointIdx, 5)
}

// markEndpoint429 handles HTTP 429 (rate-limited). Shorter self-heal than a
// full quota exhaustion: jump to failCount floor = 3 → next hit → 4 → 24 s TTL.
func (c *Client) markEndpoint429(endpointIdx int) {
	c.markEndpointFailureWith(endpointIdx, 3)
}

// markEndpointHardFailure is used when classifyRelayErrorBody identifies a quota
// or auth error inside an HTML/JSON error page (even when HTTP status was 200).
// Same backoff tier as markEndpoint403.
func (c *Client) markEndpointHardFailure(endpointIdx int) {
	c.markEndpointFailureWith(endpointIdx, 5)
}

// markEndpointFailureWith is the shared implementation. minFailCount is a floor
// applied before incrementing so callers can skip the slow 3-48 s ramp for
// failure classes known not to self-heal quickly (quota, auth, rate-limit).
// Pass 0 for the standard ramp.
func (c *Client) markEndpointFailureWith(endpointIdx, minFailCount int) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	wasHealthy := ep.failCount == 0
	if minFailCount > 0 && ep.failCount < minFailCount {
		ep.failCount = minFailCount
	}
	ep.failCount++
	ep.statsFail++
	ep.localNetworkOffline = false
	ttl := endpointBlacklistTTL(ep.failCount)
	ep.blacklistedTill = time.Now().Add(ttl)
	url := ep.url
	failCount := ep.failCount
	c.endpointMu.Unlock()
	// Only log on the healthy → blacklisted transition; subsequent failures
	// of an already-blacklisted endpoint would be log noise.
	if wasHealthy {
		log.Printf("[carrier] endpoint %s blacklisted for %s (still rotating across %d others)",
			ShortScriptKey(url), ttl.Round(100*time.Millisecond), len(c.endpoints)-1)
	} else if failCount == 8 {
		// Notify once when an endpoint reaches hour-scale backoff so the operator
		// knows this deployment is likely quota-exhausted or dead.
		log.Printf("[carrier] endpoint %s repeatedly failing (%d consecutive); now at extended backoff (%s). Consider re-deploying that script.",
			ShortScriptKey(url), failCount, ttl.Round(time.Second))
	}
}

func endpointBlacklistTTL(failCount int) time.Duration {
	if failCount <= 0 {
		return 0
	}
	if failCount <= 5 {
		return endpointBlacklistBaseTTL << (failCount - 1)
	}
	switch failCount {
	case 6:
		return 5 * time.Minute
	case 7:
		return 30 * time.Minute
	default:
		return endpointBlacklistMaxTTL
	}
}

// ShortScriptKey returns a human-readable abbreviation of an Apps Script /exec
// URL suitable for log lines. For canonical script.google.com URLs the long
// Deployment ID is truncated to "AKfycb...XXXXXX"; for direct relay URLs (when
// fronting is off) it falls back to the host. Used by cmd/client startup logs
// and by every [carrier] log line so the operator can tell endpoints apart
// without leaking the full Deployment ID.
func ShortScriptKey(scriptURL string) string {
	parts := strings.Split(strings.Trim(scriptURL, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "s" {
			id := parts[i+1]
			if len(id) > 14 {
				return id[:6] + "..." + id[len(id)-6:]
			}
			return id
		}
	}
	if len(parts) >= 3 {
		return parts[2] // direct relay URL: fall back to host
	}
	return scriptURL
}
