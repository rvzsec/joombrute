package joomla

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIsHex32(t *testing.T) {
	cases := map[string]bool{
		"a3f8c2d1e4b7f9a0c5d2e8f1b4a7c3d6": true,
		"0123456789abcdef0123456789abcdef": true,
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": false, // uppercase not accepted
		"a3f8c2d1e4b7f9a0c5d2e8f1b4a7c3d":  false, // 31 chars
		"a3f8c2d1e4b7f9a0c5d2e8f1b4a7c3d6g": false, // 33 chars
		"":                                 false,
		"not-a-hex-string-not-a-hex-string": false,
	}
	for s, want := range cases {
		if got := isHex32(s); got != want {
			t.Errorf("isHex32(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestResolveAction(t *testing.T) {
	const base = "http://target/administrator/"
	cases := []struct {
		name, action, want string
	}{
		{"empty", "", base},
		{"absolute http", "http://other/x", "http://other/x"},
		{"absolute https", "https://x.y/", "https://x.y/"},
		{"absolute path", "/administrator/index.php", "http://target/administrator/index.php"},
		{"relative", "index.php", "http://target/administrator/index.php"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveAction(base, tc.action)
			if got != tc.want {
				t.Errorf("resolveAction(%q, %q) = %q, want %q",
					base, tc.action, got, tc.want)
			}
		})
	}
}

// TestFetchLoginFormRealFixtures spins up a tiny httptest server that
// serves the captured J3/J4/J5 admin login HTML and verifies the parser
// extracts the CSRF token, action URL, and "return" value correctly.
// This is the closest thing to a regression test for the live behavior
// since the same HTML is what hits the parser in production.
func TestFetchLoginFormRealFixtures(t *testing.T) {
	cases := []string{"login_j3.html", "login_j4.html", "login_j5.html"}
	for _, fname := range cases {
		t.Run(fname, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "joomla", fname))
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Set-Cookie", "joomla_session=fixture; path=/")
				w.WriteHeader(http.StatusOK)
				_, _ = io.Copy(w, mustReader(body))
			}))
			defer srv.Close()

			jar, _ := cookiejar.New(nil)
			client := &http.Client{Jar: jar}
			tgt, err := NewTarget(srv.URL)
			if err != nil {
				t.Fatal(err)
			}

			form, err := FetchLoginForm(context.Background(), client, tgt)
			if err != nil {
				t.Fatalf("FetchLoginForm: %v", err)
			}
			if !isHex32(form.TokenName) {
				t.Errorf("TokenName not 32-hex: %q", form.TokenName)
			}
			if form.Action == "" {
				t.Errorf("Action is empty")
			}
			if form.ReturnValue == "" {
				t.Errorf("ReturnValue is empty")
			}
		})
	}
}

type readerAt struct {
	b   []byte
	pos int
}

func (r *readerAt) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

func mustReader(b []byte) io.Reader {
	return &readerAt{b: b}
}
