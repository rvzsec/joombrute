package joomla

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/rvzsec/joombrute/internal/httpx"
)

// MajorVersion is the Joomla generation. We only branch behavior on the major
// because all known parser/endpoint shifts happen at major boundaries (3 -> 4
// admin form refactor; 4 -> 5 mostly compatible but new CVEs apply).
type MajorVersion int

const (
	VersionUnknown MajorVersion = 0
	Version3       MajorVersion = 3
	Version4       MajorVersion = 4
	Version5       MajorVersion = 5
)

func (v MajorVersion) String() string {
	switch v {
	case Version3:
		return "Joomla 3.x"
	case Version4:
		return "Joomla 4.x"
	case Version5:
		return "Joomla 5.x"
	default:
		return "unknown"
	}
}

// VersionInfo is what Detect returns.
type VersionInfo struct {
	Major MajorVersion
	// Exact is the full version string when we can find it (e.g. "4.2.7").
	// Empty if we could only infer the major.
	Exact string
	// Source is how we got the version: "manifest" | "generator" | "fingerprint".
	Source string
}

// joomlaManifest mirrors the bits of /administrator/manifests/files/joomla.xml
// we care about.
type joomlaManifest struct {
	XMLName xml.Name `xml:"extension"`
	Version string   `xml:"version"`
}

var (
	// <meta name="generator" content="Joomla! - Open Source Content Management">
	// J4/J5 also sometimes ship the version after a dash.
	reGeneratorMeta = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']Joomla!?[^"']*["']`)
	// Version embedded in CSS/JS asset paths like /media/...?<version>
	reAssetVersion = regexp.MustCompile(`/media/[^"']+\?([0-9a-f]{8,32})`)
)

// Detect fingerprints the Joomla major version of t.
//
// Strategy, fastest-and-most-reliable first:
//  1. GET /administrator/manifests/files/joomla.xml - exact version if not blocked
//  2. GET / - look for <meta name="generator" content="Joomla...">
//  3. GET /administrator/ - look for J4/J5-only admin assets vs J3 markers
//
// Returns the best result; an unknown is still a usable signal upstream.
func Detect(ctx context.Context, client *http.Client, t *Target) (VersionInfo, error) {
	// 1. Manifest XML - exact version when present.
	if v, ok := detectViaManifest(ctx, client, t); ok {
		return v, nil
	}

	// 2. Generator meta on frontend.
	if v, ok := detectViaGenerator(ctx, client, t); ok {
		return v, nil
	}

	// 3. Admin login page fingerprints.
	if v, ok := detectViaAdminFingerprint(ctx, client, t); ok {
		return v, nil
	}

	return VersionInfo{Major: VersionUnknown}, fmt.Errorf("could not determine Joomla version")
}

func detectViaManifest(ctx context.Context, client *http.Client, t *Target) (VersionInfo, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.ManifestURL(), nil)
	if err != nil {
		return VersionInfo{}, false
	}
	httpx.SetUA(req, "")
	resp, err := client.Do(req)
	if err != nil {
		return VersionInfo{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return VersionInfo{}, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return VersionInfo{}, false
	}
	var m joomlaManifest
	if err := xml.Unmarshal(body, &m); err != nil {
		return VersionInfo{}, false
	}
	if m.Version == "" {
		return VersionInfo{}, false
	}
	return VersionInfo{
		Major:  majorFromString(m.Version),
		Exact:  m.Version,
		Source: "manifest",
	}, true
}

func detectViaGenerator(ctx context.Context, client *http.Client, t *Target) (VersionInfo, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.FrontendURL(), nil)
	if err != nil {
		return VersionInfo{}, false
	}
	httpx.SetUA(req, "")
	resp, err := client.Do(req)
	if err != nil {
		return VersionInfo{}, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return VersionInfo{}, false
	}
	if !reGeneratorMeta.Match(body) {
		return VersionInfo{}, false
	}
	// We know it's Joomla but generator usually has no version. Try to infer
	// the major from asset paths.
	major := inferMajorFromBody(body)
	return VersionInfo{Major: major, Source: "generator"}, major != VersionUnknown || true
}

func detectViaAdminFingerprint(ctx context.Context, client *http.Client, t *Target) (VersionInfo, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.AdminURL(), nil)
	if err != nil {
		return VersionInfo{}, false
	}
	httpx.SetUA(req, "")
	resp, err := client.Do(req)
	if err != nil {
		return VersionInfo{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return VersionInfo{}, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return VersionInfo{}, false
	}
	major := inferMajorFromBody(body)
	if major == VersionUnknown {
		return VersionInfo{}, false
	}
	return VersionInfo{Major: major, Source: "fingerprint"}, true
}

// inferMajorFromBody applies layered markup fingerprints. The ordering
// matters - J5 must be checked BEFORE J4 because J5 still carries every
// J4 marker. Markers were derived by diffing real lab responses
// (login_j3/4/5.html in testdata).
//
//   Joomla 3: Bootstrap 2/3, "templates/isis", "form-inline" class.
//   Joomla 4: Atum admin template, "templates/administrator", Bootstrap 5.
//   Joomla 5: Atum + native web components (joomla-dialog, webcomponents-
//             bundle, importmap, data-color-scheme-os) - none of those
//             exist in J4.
func inferMajorFromBody(body []byte) MajorVersion {
	lower := strings.ToLower(string(body))

	// J3 markers are mutually exclusive with J4/J5 (different template,
	// different Bootstrap), so they go first as a fast-path.
	if strings.Contains(lower, "/templates/isis/") ||
		strings.Contains(lower, `class="form-inline"`) ||
		strings.Contains(lower, "alert-message") {
		return Version3
	}

	// J5-specific markers - MUST be checked before J4 fallback. These
	// were captured from a live joomla:5-php8.2-apache image.
	switch {
	case strings.Contains(lower, "joomla-dialog"),
		strings.Contains(lower, "webcomponents-bundle"),
		strings.Contains(lower, "webcomponentsjs"),
		strings.Contains(lower, `data-color-scheme-os`),
		strings.Contains(lower, "<script type=\"importmap\""),
		strings.Contains(lower, "joomla-core-loader"):
		return Version5
	}

	// J4 fallback: anything that looks like Atum / J4+ admin but didn't
	// hit any J5-specific marker above.
	if strings.Contains(lower, "/templates/administrator/") ||
		strings.Contains(lower, `class="form-validate"`) ||
		strings.Contains(lower, "mod-login-username") {
		return Version4
	}

	return VersionUnknown
}

// majorFromString parses a manifest version string like "4.2.7" -> Version4.
func majorFromString(v string) MajorVersion {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) == 0 {
		return VersionUnknown
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return VersionUnknown
	}
	switch n {
	case 3:
		return Version3
	case 4:
		return Version4
	case 5:
		return Version5
	}
	return VersionUnknown
}
