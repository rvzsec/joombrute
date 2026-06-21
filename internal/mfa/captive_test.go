package mfa

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIsHex32MFA(t *testing.T) {
	if !isHex32("a3f8c2d1e4b7f9a0c5d2e8f1b4a7c3d6") {
		t.Error("expected true for valid 32-hex")
	}
	if isHex32("short") {
		t.Error("expected false for short string")
	}
}

func TestResolveCaptiveAction(t *testing.T) {
	const page = "http://target/administrator/index.php?option=com_users&view=captive"
	cases := []struct {
		name, action, want string
	}{
		{"empty -> pageURL", "", page},
		{"absolute http", "http://other/x", "http://other/x"},
		{
			"absolute path with query - regression: literal ? must NOT become %3F",
			"/administrator/index.php?option=com_users&task=captive.validate&record_id=1",
			"http://target/administrator/index.php?option=com_users&task=captive.validate&record_id=1",
		},
		{
			"relative action",
			"index.php?task=foo",
			"http://target/administrator/index.php?task=foo",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveCaptiveAction(page, tc.action)
			if got != tc.want {
				t.Errorf("got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestFetchCaptiveFormParsesJ4 verifies the captive form parser locates
// the form by its task=captive.validate action signature (the J4 form
// has no stable id) and extracts both the 32-hex CSRF token and the
// HTML-decoded action URL.
func TestFetchCaptiveFormParsesJ4(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "mfa", "captive_j4.html"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	f, err := FetchCaptiveForm(context.Background(), client, srv.URL+"/captive")
	if err != nil {
		t.Fatalf("FetchCaptiveForm: %v", err)
	}
	if !isHex32(f.TokenName) {
		t.Errorf("TokenName = %q, expected 32-hex", f.TokenName)
	}
	if f.Action == "" {
		t.Errorf("Action is empty")
	}
	// Regression: the action MUST contain a literal "?" - earlier bug
	// URL-encoded it to %3F and the captive POST hit a 404.
	if want := "task=captive.validate"; !contains(f.Action, want) {
		t.Errorf("Action %q missing %q", f.Action, want)
	}
}

func TestParseRange(t *testing.T) {
	cases := []struct {
		name, start, end string
		wantStart, wantEnd int
		wantErr          bool
	}{
		{"defaults", "", "", 0, 999999, false},
		{"explicit narrow", "000010", "000020", 10, 20, false},
		{"start > end", "000020", "000010", 0, 0, true},
		{"non-digit", "abcdef", "000099", 0, 0, true},
		{"wrong length", "1234", "999999", 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, e, err := parseRange(tc.start, tc.end)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected err, got start=%d end=%d", s, e)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if s != tc.wantStart || e != tc.wantEnd {
				t.Errorf("got (%d,%d), want (%d,%d)", s, e, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
