package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rvzsec/joombrute/internal/joomla"
)

// TestFetchUsersFixture verifies the user list JSON:API parser against
// the real response shape J4.2.7 returns.
func TestFetchUsersFixture(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "recon", "users_j4.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	users, err := fetchUsers(context.Background(), srv.Client(), srv.URL+"/api/index.php/v1/users")
	if err != nil {
		t.Fatalf("fetchUsers: %v", err)
	}
	if len(users) == 0 {
		t.Fatal("expected >=1 user in fixture")
	}
	if users[0].Username == "" {
		t.Errorf("first user has empty username: %+v", users[0])
	}
}

// TestFetchConfigMergesAttributes is the regression test for the bug
// where my parser only read the first JSON:API data item and missed all
// the other config keys (host, user, password, db were all empty).
//
// The real J4 /api/index.php/v1/config/application response returns ONE
// attribute per data entry - so we must merge across all entries.
func TestFetchConfigMergesAttributes(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "recon", "config_j4.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	cfg, err := fetchConfig(context.Background(), srv.Client(),
		srv.URL+"/api/index.php/v1/config/application")
	if err != nil {
		t.Fatalf("fetchConfig: %v", err)
	}
	// The lab seeded db.host = joombrute-j4-db, db.user = joomla,
	// db.password = joomlapass_j4 - assert merge worked.
	if cfg.DBHost == "" {
		t.Errorf("DBHost empty (merge failed)")
	}
	if cfg.DBUser == "" {
		t.Errorf("DBUser empty (merge failed)")
	}
	if cfg.DBPass == "" {
		t.Errorf("DBPass empty (merge failed)")
	}
	if cfg.DBPrefix == "" {
		t.Errorf("DBPrefix empty (merge failed)")
	}
	if !strings.Contains(cfg.DBPass, "joomlapass") {
		t.Errorf("DBPass=%q does not look like the lab seeded value", cfg.DBPass)
	}
}

// TestUsernamesDedupesAndExcludesBlocked confirms the helper we feed
// into the bruteforce pipeline doesn't waste attempts on blocked users
// or emit duplicates.
func TestUsernamesDedupesAndExcludesBlocked(t *testing.T) {
	res := CVE2023_23752Result{
		Users: []User{
			{Username: "admin", Block: 0},
			{Username: "alice", Block: 0},
			{Username: "blocked", Block: 1},
			{Username: "admin", Block: 0}, // duplicate
			{Username: "  ", Block: 0},    // whitespace-only ignored
		},
	}
	got := res.Usernames()
	want := []string{"admin", "alice"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, u := range want {
		if got[i] != u {
			t.Errorf("[%d] got %q, want %q", i, got[i], u)
		}
	}
}

// TestNonOKReturnsEmpty validates the patched-target case: 401/404
// must NOT raise an error to the caller and must produce no findings.
func TestNonOKReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "patched", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tgt, _ := joomla.NewTarget(srv.URL)
	res, err := RunCVE2023_23752(context.Background(), srv.Client(), tgt)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.HasFindings() {
		t.Errorf("HasFindings should be false on patched target")
	}
}
