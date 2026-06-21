package brute

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rvzsec/joombrute/internal/joomla"
	"github.com/rvzsec/joombrute/internal/output"
)

// silentSink discards everything - keeps test output clean.
type silentSink struct{}

func (silentSink) Hit(output.Hit)                    {}
func (silentSink) Infof(string, ...any)              {}
func (silentSink) Warnf(string, ...any)              {}
func (silentSink) Errorf(string, ...any)             {}
func (silentSink) Debugf(string, ...any)             {}

// mockJoomla is a minimal in-process Joomla replica that serves a real
// login page + classifies POSTs by a configurable rule. Lets us drive
// brute.Run end-to-end against a knob-controlled backend so we can
// exercise --backoff (returns 429 after N reqs) and --refresh-every
// (rotates session token per N reqs) deterministically.
type mockJoomla struct {
	mu sync.Mutex
	// blockAfter > 0 means start returning 429 after this many POSTs.
	blockAfter int64
	postCount  int64
	// rotateEvery > 0 means rotate the CSRF token every N requests.
	rotateEvery int64
	tokenIdx    int64
	formFetches int64
	// failFormFetchN: return 500 on the first N form GETs, then 200.
	// Models Joomla's session-init race that returned 500 on HTB.
	failFormFetchN int64
	traceFn        func(string)
	// successFor declares which (user, pass) is the correct combo.
	successFor map[string]string
	// rejectAfterMFAFlag toggles MFA captive on the success response.
	mfaRequired bool
}

func (m *mockJoomla) currentToken() string {
	// Generate a deterministic but rotating 32-hex token.
	idx := atomic.LoadInt64(&m.tokenIdx)
	hexFmt := fmt.Sprintf("%032x", idx)
	if len(hexFmt) > 32 {
		hexFmt = hexFmt[:32]
	}
	// Fill prefix with 'a' so it's always 32 chars and looks plausible.
	if len(hexFmt) < 32 {
		hexFmt = strings.Repeat("a", 32-len(hexFmt)) + hexFmt
	}
	return hexFmt
}

func (m *mockJoomla) handler() http.Handler {
	const loginHTMLTpl = `<!doctype html>
<html><body>
<form id="form-login" action="/administrator/index.php" method="post" class="form-validate">
  <input type="text"  id="mod-login-username" name="username" />
  <input type="password" name="passwd" />
  <input type="hidden" name="option" value="com_login">
  <input type="hidden" name="task"   value="login">
  <input type="hidden" name="return" value="aW5kZXgucGhw">
  <input type="hidden" name="%s" value="1">
</form>
</body></html>`

	const successHTML = `<!doctype html><html><body>
<div id="cpanel">control panel - com_cpanel</div></body></html>`

	const failHTML = `<!doctype html><html><body>
<form id="form-login" action="/administrator/index.php" method="post">
  <input id="mod-login-username" name="username" />
</form>
<div>Username and password do not match.</div>
</body></html>`

	mux := http.NewServeMux()

	// GET /administrator/ returns the login form with the *current* token.
	// Optionally returns 500 on the first failFormFetchN fetches to model
	// the Joomla session-init race that bites under concurrent startup.
	mux.HandleFunc("/administrator/", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&m.formFetches, 1)
		if m.failFormFetchN > 0 && n <= m.failFormFetchN {
			if m.traceFn != nil {
				m.traceFn(fmt.Sprintf("GET form #%d -> 500 (simulated session race)", n))
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tok := m.currentToken()
		if m.traceFn != nil {
			m.traceFn(fmt.Sprintf("GET form #%d -> token=%s", n, tok))
		}
		fmt.Fprintf(w, loginHTMLTpl, tok)
	})

	// GET /administrator/index.php is the post-login landing page - 
	// classifier follows the 303 here and uses body markers. We branch
	// on r.URL.Query() to mirror what the POST handler chose.
	mux.HandleFunc("/administrator/index.php", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			q := r.URL.Query()
			out := q.Get("outcome")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			switch {
			case q.Get("option") == "com_users" && q.Get("view") == "captive":
				_, _ = w.Write([]byte(`<html><body>captive-form two-factor authentication method</body></html>`))
			case out == "ok":
				_, _ = w.Write([]byte(successHTML))
			default:
				_, _ = w.Write([]byte(failHTML))
			}
		case http.MethodPost:
			n := atomic.AddInt64(&m.postCount, 1)
			// Rate-limit branch - check BEFORE token rotation so a
			// blocked attempt doesn't side-effect the token.
			if m.blockAfter > 0 && n > m.blockAfter {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			// Read form, classify against the *current* token (rotation
			// happens AFTER the check, mirroring real Joomla rotating on
			// successful state transitions, not on the validation step).
			_ = r.ParseForm()
			user := r.PostForm.Get("username")
			pass := r.PostForm.Get("passwd")
			tok := m.currentToken()
			tokenOK := r.PostForm.Get(tok) == "1"
			if m.traceFn != nil {
				m.traceFn(fmt.Sprintf("POST n=%d user=%s pass=%s submitted-token-present-for-%s=%v",
					n, user, pass, tok, tokenOK))
			}
			// Rotate AFTER the check if configured.
			if m.rotateEvery > 0 && n%m.rotateEvery == 0 {
				atomic.AddInt64(&m.tokenIdx, 1)
			}
			if !tokenOK {
				redirect303(w, "/administrator/index.php?outcome=fail")
				return
			}
			if wantPass, ok := m.successFor[user]; ok && pass == wantPass {
				if m.mfaRequired {
					redirect303(w, "/administrator/index.php?option=com_users&view=captive")
					return
				}
				redirect303(w, "/administrator/index.php?outcome=ok")
				return
			}
			redirect303(w, "/administrator/index.php?outcome=fail")
		}
	})

	// NOTE: Go's mux strips query strings before matching, so we cannot
	// register "/administrator/index.php?option=com_users&view=captive"
	// directly. The same /administrator/index.php handler above branches
	// on r.URL.Query() to serve captive content when option=com_users
	// and view=captive are present.
	return mux
}

func redirect303(w http.ResponseWriter, loc string) {
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusSeeOther)
}

func writeTempWordlist(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "pw.txt")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestBackoffOn429 confirms that a 429 from the target triggers the
// blocked-back-off branch and does NOT count as a false success.
func TestBackoffOn429(t *testing.T) {
	mj := &mockJoomla{
		blockAfter: 1, // start blocking after the first POST
		successFor: map[string]string{"admin": "rightpass"},
	}
	srv := httptest.NewServer(mj.handler())
	defer srv.Close()

	tgt, err := joomla.NewTarget(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	wordlist := writeTempWordlist(t, "p1", "p2", "p3", "p4", "p5")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := Run(ctx, Config{
		Target:         tgt,
		Usernames:      []string{"admin"},
		PasswordFile:   wordlist,
		Concurrency:    2,
		RequestTimeout: 2 * time.Second,
		BackoffBlocked: 100 * time.Millisecond,
		Sink:           silentSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("stats=%+v", stats)
	if stats.Blocked == 0 {
		t.Errorf("expected Blocked > 0, got stats=%+v", stats)
	}
	if stats.Valid != 0 {
		t.Errorf("expected Valid == 0 (no false positive under 429), got %d FirstHit=%+v",
			stats.Valid, stats.FirstHit)
	}
}

// TestRefreshEveryHandlesTokenRotation confirms --refresh-every=1 keeps
// the worker functional when the backend rotates its CSRF token every
// request. Without --refresh-every, every attempt after rotation fails.
func TestRefreshEveryHandlesTokenRotation(t *testing.T) {
	mj := &mockJoomla{
		rotateEvery: 1, // rotate per POST
		successFor:  map[string]string{"admin": "rightpass"},
		traceFn:     func(s string) { t.Log(s) },
	}
	srv := httptest.NewServer(mj.handler())
	defer srv.Close()

	tgt, err := joomla.NewTarget(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	// rightpass is at position 3; without refresh-every the worker uses
	// a stale token on attempts 2+ and never wins. With refresh-every=1
	// the worker re-fetches the form each iteration and finds it.
	wordlist := writeTempWordlist(t, "p1", "p2", "rightpass", "p4")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := Run(ctx, Config{
		Target:         tgt,
		Usernames:      []string{"admin"},
		PasswordFile:   wordlist,
		Concurrency:    1,
		RefreshEvery:   1, // <-- the knob under test
		RequestTimeout: 2 * time.Second,
		StopOnSuccess:  true,
		Sink:           silentSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Valid != 1 {
		t.Errorf("expected Valid=1 with refresh-every, got %+v", stats)
	}
	if stats.FirstHit == nil || stats.FirstHit.Password != "rightpass" {
		t.Errorf("expected FirstHit=rightpass, got %+v", stats.FirstHit)
	}
}

// TestNoRefreshWithRotationFails is the negative twin of the above - 
// without --refresh-every the worker uses a stale token after rotation
// and the win is missed. Confirms RefreshEvery actually matters.
func TestNoRefreshWithRotationFails(t *testing.T) {
	mj := &mockJoomla{
		rotateEvery: 1,
		successFor:  map[string]string{"admin": "rightpass"},
	}
	srv := httptest.NewServer(mj.handler())
	defer srv.Close()

	tgt, _ := joomla.NewTarget(srv.URL)
	wordlist := writeTempWordlist(t, "p1", "p2", "rightpass", "p4")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := Run(ctx, Config{
		Target:         tgt,
		Usernames:      []string{"admin"},
		PasswordFile:   wordlist,
		Concurrency:    1,
		RefreshEvery:   0, // disabled - token will go stale
		RequestTimeout: 2 * time.Second,
		Sink:           silentSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Valid != 0 {
		t.Errorf("expected Valid=0 without refresh under rotation, got %+v", stats)
	}
}

// TestMFACaptureFirstHit asserts that an MFA-required outcome is
// captured in FirstHit so `chain` can pivot into mfa-bypass.
func TestMFACaptureFirstHit(t *testing.T) {
	mj := &mockJoomla{
		successFor:  map[string]string{"admin": "rightpass"},
		mfaRequired: true,
	}
	srv := httptest.NewServer(mj.handler())
	defer srv.Close()

	tgt, _ := joomla.NewTarget(srv.URL)
	wordlist := writeTempWordlist(t, "p1", "rightpass", "p3")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := Run(ctx, Config{
		Target:         tgt,
		Usernames:      []string{"admin"},
		PasswordFile:   wordlist,
		Concurrency:    1,
		StopOnMFA:      true,
		RequestTimeout: 2 * time.Second,
		Sink:           silentSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.MFAGuarded != 1 {
		t.Errorf("expected MFAGuarded=1, got %+v", stats)
	}
	if stats.FirstHit == nil || stats.FirstHit.Outcome != "mfa-required" {
		t.Errorf("expected FirstHit.Outcome=mfa-required, got %+v", stats.FirstHit)
	}
	if stats.FirstHit.Password != "rightpass" {
		t.Errorf("expected FirstHit.Password=rightpass, got %q", stats.FirstHit.Password)
	}
}

// TestFormFetchRetrySurvivesInitial500s is the regression test for the
// HTB bug where 3 of 4 workers died on the initial form fetch because
// Joomla returned 500 on a session-init race. With FormFetchAttempts=3
// each worker should survive 2 initial 500s before getting a 200 form,
// and the brute should still succeed.
//
// Without the retry fix: 5 of 6 workers die, only 1 keeps trying, brute
// usually still wins on the right password but loses 83% of throughput.
// With the retry fix: all 6 workers survive the initial 500 wave.
func TestFormFetchRetrySurvivesInitial500s(t *testing.T) {
	mj := &mockJoomla{
		// Return 500 on the first 5 form fetches across all workers.
		// With c=6 and 3 retries each, every worker gets at least one
		// 200 form within their retry budget.
		failFormFetchN: 5,
		successFor:     map[string]string{"admin": "rightpass"},
	}
	srv := httptest.NewServer(mj.handler())
	defer srv.Close()

	tgt, err := joomla.NewTarget(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	wordlist := writeTempWordlist(t, "p1", "p2", "rightpass", "p4", "p5")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stats, err := Run(ctx, Config{
		Target:            tgt,
		Usernames:         []string{"admin"},
		PasswordFile:      wordlist,
		Concurrency:       6,
		FormFetchAttempts: 3, // <-- the knob under test
		RequestTimeout:    2 * time.Second,
		StopOnSuccess:     true,
		Sink:              silentSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Valid != 1 {
		t.Errorf("expected Valid=1 (workers should survive initial 500s), got %+v", stats)
	}
	if stats.FirstHit == nil || stats.FirstHit.Password != "rightpass" {
		t.Errorf("expected FirstHit.Password=rightpass, got %+v", stats.FirstHit)
	}
	// With retries enabled, no worker should have permanently died on
	// the initial 500. Errors counter should reflect that.
	if stats.Errors > 0 {
		t.Errorf("expected Errors=0 with retry enabled, got %d (suggests a worker gave up)", stats.Errors)
	}
}

// TestFormFetchRetryExhaustsCleanly confirms a worker that exhausts its
// retry budget reports the error cleanly instead of hanging or spamming
// the sink. Sets failFormFetchN higher than attempts*workers so every
// worker MUST give up.
func TestFormFetchRetryExhaustsCleanly(t *testing.T) {
	mj := &mockJoomla{
		failFormFetchN: 1000, // every fetch fails
		successFor:     map[string]string{"admin": "rightpass"},
	}
	srv := httptest.NewServer(mj.handler())
	defer srv.Close()

	tgt, _ := joomla.NewTarget(srv.URL)
	wordlist := writeTempWordlist(t, "p1", "rightpass", "p3")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stats, err := Run(ctx, Config{
		Target:            tgt,
		Usernames:         []string{"admin"},
		PasswordFile:      wordlist,
		Concurrency:       3,
		FormFetchAttempts: 2,
		RequestTimeout:    2 * time.Second,
		Sink:              silentSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Valid != 0 {
		t.Errorf("expected Valid=0 when every form fetch 500s, got %+v", stats)
	}
	// Every worker exhausts its retry budget and reports one error.
	if stats.Errors == 0 {
		t.Errorf("expected Errors > 0 when all workers exhaust retries, got %+v", stats)
	}
}
