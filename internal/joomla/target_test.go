package joomla

import "testing"

func TestNewTarget(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"http with trailing slash", "http://target/", "http://target", false},
		{"http no trailing slash", "http://target", "http://target", false},
		{"bare hostname", "target.com", "http://target.com", false},
		{"https with subpath", "https://example.com/joomla/", "https://example.com/joomla", false},
		{"strips query", "http://x/?a=1", "http://x", false},
		{"strips fragment", "http://x/#frag", "http://x", false},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"no host", "http://", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewTarget(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Base != tc.want {
				t.Errorf("got Base=%q want %q", got.Base, tc.want)
			}
		})
	}
}

func TestTargetURLs(t *testing.T) {
	tgt, err := NewTarget("http://x.io")
	if err != nil {
		t.Fatal(err)
	}
	if tgt.AdminURL() != "http://x.io/administrator/" {
		t.Errorf("AdminURL: %s", tgt.AdminURL())
	}
	if tgt.APIPath("v1/users") != "http://x.io/api/index.php/v1/users" {
		t.Errorf("APIPath: %s", tgt.APIPath("v1/users"))
	}
	// Leading slash in suffix must be tolerated.
	if tgt.APIPath("/v1/users") != "http://x.io/api/index.php/v1/users" {
		t.Errorf("APIPath stripslash: %s", tgt.APIPath("/v1/users"))
	}
	if tgt.ManifestURL() != "http://x.io/administrator/manifests/files/joomla.xml" {
		t.Errorf("ManifestURL: %s", tgt.ManifestURL())
	}
}
