package carrier

import (
	"bytes"
	"strings"
)

// isLikelyNonBatchRelayPayload reports whether body cannot be a valid
// AES-GCM-sealed batch envelope. Used to short-circuit the (much more
// expensive) base64+AEAD decode pipeline when Apps Script returned an
// HTML/JSON error page or a v1.7.0 Code.gs plain-text sentinel.
func isLikelyNonBatchRelayPayload(body []byte) bool {
	t := bytes.TrimSpace(body)
	if len(t) == 0 {
		return false
	}
	l := bytes.ToLower(t)
	if bytes.HasPrefix(l, []byte("<!doctype")) || bytes.HasPrefix(l, []byte("<html")) {
		return true
	}
	// Base64 batches never begin with JSON object/array delimiters or raw HTTP.
	if t[0] == '{' || t[0] == '[' || bytes.HasPrefix(t, []byte("HTTP/")) {
		return true
	}
	// Code.gs sentinels emitted with HTTP 200 by v1.7.0's forwarder when it
	// caught upstream failures. v1.7.1 Code.gs throws instead of returning 200,
	// so these prefixes shouldn't appear from a redeployed script — but users
	// often forget to redeploy, so we keep the sniffer broad. Detecting the
	// prefix lets the carrier surface a clear log line instead of producing
	// "batch: base64 decode: illegal base64 data at input byte 9" noise (which
	// is what tripping past this check produces when DecodeBatch hits the
	// first colon in "Exception:" or "upstream fetch error:").
	if bytes.HasPrefix(t, []byte("Exception:")) ||
		bytes.HasPrefix(t, []byte("relay_loop_detected:")) ||
		bytes.HasPrefix(t, []byte("upstream status ")) ||
		bytes.HasPrefix(t, []byte("upstream fetch error:")) {
		return true
	}
	return false
}

// classifyRelayErrorBody inspects a non-batch response body (HTML or JSON error
// page returned by Apps Script instead of an encrypted payload) and returns a
// human-readable explanation and whether the failure is "hard" (quota / auth /
// admin — won't self-heal in seconds) or "soft" (transient Google-side error).
//
// Pattern tables are ported from MasterHttpRelayVPN relay_response.py and cover
// the error categories documented at:
//
//	developers.google.com/apps-script/guides/support/troubleshooting
//	developers.google.com/apps-script/guides/services/quotas
func classifyRelayErrorBody(body []byte) (reason string, hard bool) {
	trimmed := bytes.TrimSpace(body)
	lower := strings.ToLower(string(trimmed))

	// ── Code.gs sentinels from v1.7.0 forwarder ────────────────────────────
	// v1.7.0 Code.gs returned these strings with HTTP 200 when UrlFetchApp
	// failed; v1.7.1 throws instead, but un-redeployed scripts still emit them.
	// Classified here so users get an actionable message rather than the
	// generic "non-batch payload" log.
	if bytes.HasPrefix(trimmed, []byte("relay_loop_detected:")) {
		return "Code.gs RELAY_URLS points at script.google.com — set it to your VPS /tunnel endpoint and redeploy", true
	}
	if bytes.HasPrefix(trimmed, []byte("upstream fetch error:")) ||
		bytes.HasPrefix(trimmed, []byte("Exception:")) {
		return "Code.gs could not reach your VPS — check VPS is up, the server_port in server_config.json matches RELAY_URLS, and the VPS firewall allows inbound from Google's egress IPs", false
	}
	if bytes.HasPrefix(trimmed, []byte("upstream status ")) {
		return "VPS returned a non-200 status to Apps Script — check goose-server logs on your VPS", false
	}

	// ── Quota / rate-limit ─────────────────────────────────────────────────
	// "Service invoked too many times for one day: urlfetch."
	// "Bandwidth quota exceeded"
	quotaPatterns := []string{
		"service invoked too many times",
		"invoked too many times",
		"bandwidth quota exceeded",
		"too much upload bandwidth",
		"too much traffic",
		"urlfetch",
		"quota",
		"exceeded",
		"daily",
		"rate limit",
	}
	for _, p := range quotaPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script quota exhausted (20k requests/day limit) — " +
				"wait up to 24h for the quota to reset at midnight Pacific, " +
				"or deploy Code.gs under a second Google account and add it to script_keys", true
		}
	}

	// ── Auth / permission ──────────────────────────────────────────────────
	// "Authorization is required to perform that action."
	authPatterns := []string{
		"authorization is required",
		"unauthorized",
		"not authorized",
		"permission denied",
		"access denied",
	}
	for _, p := range authPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script auth error — check: (1) AES key matches on both sides, " +
				"(2) deployment is set to 'Execute as: Me / Anyone can access', " +
				"(3) script_keys uses the Deployment ID (not the Script ID), " +
				"(4) the owning Google account has authorised the script by running it manually", true
		}
	}

	// ── Deployment not found ───────────────────────────────────────────────
	// "Error occurred due to a missing library version or a deployment version.
	//  Error code Not_Found"
	deployPatterns := []string{
		"error code not_found",
		"not_found",
		"deployment",
		"script id",
		"scriptid",
		"no script",
	}
	for _, p := range deployPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script deployment not found — verify script_keys is the Deployment ID " +
				"(not the Script ID), the deployment is active, and you re-deployed after editing Code.gs", true
		}
	}

	// ── Admin / Workspace policy ───────────────────────────────────────────
	// "UrlFetch calls to <URL> are not permitted by your admin"
	adminPatterns := []string{
		"not permitted by your admin",
		"contact your administrator",
		"disabled. please contact",
		"domain policy has disabled",
		"administrator to enable",
	}
	for _, p := range adminPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script blocked by a Google Workspace admin policy — " +
				"either the target URL is not on the admin's UrlFetch allowlist " +
				"or a required Google service has been disabled by the domain admin", true
		}
	}

	// ── Transient Google-side errors ───────────────────────────────────────
	// "Server not available." / "Server error occurred, please try again."
	transientPatterns := []string{
		"server not available",
		"server error occurred",
		"please try again",
		"temporarily unavailable",
	}
	for _, p := range transientPatterns {
		if strings.Contains(lower, p) {
			return "Google Apps Script server temporarily unavailable — will retry", false
		}
	}

	return "", false
}
