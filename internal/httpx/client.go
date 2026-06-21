// Package httpx provides the shared HTTP plumbing used across joombrute:
// session-isolated clients, proxy support, custom user agent, redirect
// control, and a sane default timeout/transport tuned for bruteforce loads.
package httpx

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

// Config controls how a Client is constructed. Zero values are sensible.
type Config struct {
	// Timeout is the per-request timeout. Default: 15s.
	Timeout time.Duration
	// Proxy is an optional HTTP/HTTPS/SOCKS5 proxy URL (e.g. http://127.0.0.1:8080).
	Proxy string
	// UserAgent overrides the default UA. Empty = use DefaultUserAgent.
	UserAgent string
	// InsecureTLS skips cert verification (lab + WAF-fronted targets).
	InsecureTLS bool
	// FollowRedirects: if false, redirects are returned as-is so callers can
	// inspect the Location header (critical for login success detection).
	FollowRedirects bool
	// MaxIdleConns is the transport pool size. Default: 100.
	MaxIdleConns int
}

// DefaultUserAgent is what we send by default. Innocuous-looking.
const DefaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// New builds a *http.Client with its own cookie jar - i.e. a fresh session.
// Use one Client per bruteforce worker so sessions don't bleed across attempts.
func New(cfg Config) (*http.Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 100
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookiejar: %w", err)
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConns,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureTLS, //nolint:gosec // explicit opt-in for lab/WAF
		},
	}

	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("parse proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}

	c := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: tr,
		Jar:       jar,
	}

	if !cfg.FollowRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return c, nil
}

// SetUA stamps the user-agent header on a request, preferring cfg.UserAgent
// if set, otherwise DefaultUserAgent.
func SetUA(req *http.Request, ua string) {
	if ua == "" {
		ua = DefaultUserAgent
	}
	req.Header.Set("User-Agent", ua)
}
