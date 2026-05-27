package carrier

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	// Local offline failures should not ramp a mobile client into the 30m/1h
	// endpoint penalty box. Keep the pause long enough to avoid a tight retry
	// loop while airplane mode is on, but short enough that new sessions recover
	// quickly when the network returns.
	localNetworkOfflineBlacklistTTL = 15 * time.Second
	localNetworkRecoveryProbeEvery  = 5 * time.Second
	localNetworkRecoveryProbeTO     = 2 * time.Second
)

func isLocalNetworkOffline(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout || dnsErr.IsTemporary || dnsErr.IsNotFound {
			return true
		}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && strings.EqualFold(opErr.Op, "dial") {
		if opErr.Timeout() || errors.Is(opErr.Err, context.DeadlineExceeded) {
			return true
		}
	}
	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) && isLocalOfflineSyscall(syscallErr.Err) {
		return true
	}
	if isLocalOfflineSyscall(err) {
		return true
	}

	// Last-resort fallback for platform-specific wrapped messages, especially
	// Windows WSA errors whose Errno values do not always compare cleanly after
	// net/http wraps them in url.Error/net.OpError.
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"network is unreachable",
		"unreachable network",
		"no route to host",
		"network is down",
		"host is down",
		"host is unreachable",
		"temporary failure in name resolution",
		"no such host",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// isLocalOfflineSyscall checks errno values that indicate the local network
// stack is offline. The set is intentionally restricted to errnos defined on
// every supported platform (Linux/macOS/Windows). Linux-only ENONET ("machine
// is not on the network") is covered by the message-substring fallback in
// isLocalNetworkOffline.
func isLocalOfflineSyscall(err error) bool {
	for _, target := range []error{
		syscall.ENETUNREACH,
		syscall.EHOSTUNREACH,
		syscall.ENETDOWN,
		syscall.EHOSTDOWN,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func recoveryProbeAddress(cfg Config) string {
	addr := strings.TrimSpace(cfg.Fronting.GoogleIP)
	if addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "443")
}

func (c *Client) runEndpointRecoveryLoop(ctx context.Context) {
	if c.recoveryProbeAddr == "" {
		return
	}
	t := time.NewTicker(localNetworkRecoveryProbeEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if c.runEndpointRecoveryProbeOnce(ctx) {
				c.wake.Broadcast()
			}
		}
	}
}

func (c *Client) runEndpointRecoveryProbeOnce(ctx context.Context) bool {
	if c.recoveryProbeAddr == "" || !c.shouldRunLocalNetworkRecoveryProbe() {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, localNetworkRecoveryProbeTO)
	defer cancel()
	dialer := net.Dialer{Timeout: localNetworkRecoveryProbeTO}
	conn, err := dialer.DialContext(probeCtx, "tcp", c.recoveryProbeAddr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	cleared := c.resetLocalNetworkFailures()
	if cleared > 0 {
		log.Printf("[carrier] local network appears reachable again; cleared %d local-offline endpoint backoff(s)", cleared)
	}
	return cleared > 0
}

func (c *Client) shouldRunLocalNetworkRecoveryProbe() bool {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if len(c.endpoints) == 0 {
		return false
	}
	now := time.Now()
	allUnavailable := true
	hasLocalOffline := false
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if !ep.blacklistedTill.After(now) {
			allUnavailable = false
			break
		}
		if ep.localNetworkOffline && ep.blacklistedTill.After(now) {
			hasLocalOffline = true
		}
	}
	return allUnavailable && hasLocalOffline
}

func (c *Client) resetLocalNetworkFailures() int {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	cleared := 0
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if !ep.localNetworkOffline {
			continue
		}
		ep.blacklistedTill = time.Time{}
		ep.failCount = 0
		ep.localNetworkOffline = false
		cleared++
	}
	return cleared
}

func (c *Client) markEndpointLocalNetworkFailure(endpointIdx int) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	wasHealthy := ep.failCount == 0 && !ep.blacklistedTill.After(time.Now())
	ep.failCount = 0
	ep.statsFail++
	ep.localNetworkOffline = true
	ep.blacklistedTill = time.Now().Add(localNetworkOfflineBlacklistTTL)
	url := ep.url
	peerCount := len(c.endpoints) - 1
	c.endpointMu.Unlock()
	if wasHealthy {
		log.Printf("[carrier] endpoint %s local network offline; retrying in %s (still rotating across %d others)",
			ShortScriptKey(url), localNetworkOfflineBlacklistTTL.Round(time.Second), peerCount)
	}
}
