// Package joomla holds Joomla-specific knowledge: URL construction, version
// detection, admin form parsing, and login-response classification.
//
// Everything in this package is read-only against the target - no credential
// attempts happen here. The brute and mfa packages drive the actual attacks.
package joomla

import (
	"fmt"
	"net/url"
	"strings"
)

// Target is a Joomla site under test. Construct via NewTarget so the URL is
// validated and normalized once.
type Target struct {
	// Base is the canonical site root, no trailing slash. e.g. "http://10.0.0.1"
	Base string
}

// NewTarget validates and normalizes the supplied URL.
//
// Accepts forms like:
//
//	http://target/
//	https://target.com/joomla
//	target.com         (assumes http://)
func NewTarget(raw string) (*Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("target has no host: %q", raw)
	}

	// Strip trailing slash from path for clean joining.
	u.Path = strings.TrimRight(u.Path, "/")
	// Drop fragments/query - they don't apply to the base.
	u.RawQuery = ""
	u.Fragment = ""

	return &Target{Base: u.String()}, nil
}

// AdminURL returns the admin login URL: <base>/administrator/.
//
// Joomla 3.x, 4.x, and 5.x all use this path by default. Custom admin paths
// (via security plugins like Admin Tools) are out of scope for v1.
func (t *Target) AdminURL() string {
	return t.Base + "/administrator/"
}

// APIPath returns a path under the Webservices API base (Joomla 4+).
//
// Example: t.APIPath("v1/users") -> "<base>/api/index.php/v1/users".
func (t *Target) APIPath(suffix string) string {
	suffix = strings.TrimLeft(suffix, "/")
	return t.Base + "/api/index.php/" + suffix
}

// ManifestURL is the public Joomla version manifest: leaks the exact version
// even on patched sites unless the admin manually removes it.
func (t *Target) ManifestURL() string {
	return t.Base + "/administrator/manifests/files/joomla.xml"
}

// FrontendURL is the public site root, used for <meta name="generator"> sniffing.
func (t *Target) FrontendURL() string {
	return t.Base + "/"
}

// String implements fmt.Stringer for clean log output.
func (t *Target) String() string { return t.Base }
