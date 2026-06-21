package main

import (
	"context"
	"fmt"
	"time"

	"github.com/rvzsec/joombrute/internal/httpx"
	"github.com/rvzsec/joombrute/internal/joomla"
	"github.com/spf13/cobra"
)

func newDetectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Fingerprint Joomla version (3.x / 4.x / 5.x)",
		Long: `Detect the Joomla major (and exact, when leakable) version on the target.

Tries, in order:
  1. /administrator/manifests/files/joomla.xml  (exact version when not blocked)
  2. <meta name="generator"> on the frontend
  3. Admin login page markup fingerprints (Bootstrap classes, template paths)`,
		RunE: runDetect,
	}
	return cmd
}

func runDetect(_ *cobra.Command, _ []string) error {
	if gflags.URL == "" {
		return fmt.Errorf("--url is required")
	}
	sink, closer := buildSink()
	defer closer()

	t, err := joomla.NewTarget(gflags.URL)
	if err != nil {
		return err
	}

	client, err := httpx.New(httpx.Config{
		Timeout:         10 * time.Second,
		Proxy:           gflags.Proxy,
		UserAgent:       gflags.UserAgent,
		InsecureTLS:     gflags.InsecureTLS,
		FollowRedirects: true,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info, err := joomla.Detect(ctx, client, t)
	if err != nil {
		sink.Warnf("detection inconclusive: %v", err)
	}

	if info.Exact != "" {
		sink.Infof("target=%s  version=%s  major=%s  source=%s",
			t.String(), info.Exact, info.Major, info.Source)
	} else {
		sink.Infof("target=%s  major=%s  source=%s",
			t.String(), info.Major, info.Source)
	}
	return nil
}
