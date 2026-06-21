package joomla

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"
)

func TestInferMajorFromBody(t *testing.T) {
	cases := []struct {
		name string
		file string
		want MajorVersion
	}{
		{"j3 admin login", "login_j3.html", Version3},
		{"j4 admin login", "login_j4.html", Version4},
		{"j5 admin login", "login_j5.html", Version5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "joomla", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			got := inferMajorFromBody(body)
			if got != tc.want {
				t.Errorf("inferMajorFromBody(%s) = %v, want %v", tc.file, got, tc.want)
			}
		})
	}
}

func TestManifestParse(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "joomla", "manifest_j4.xml"))
	if err != nil {
		t.Fatal(err)
	}
	var m joomlaManifest
	if err := xml.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.Version != "4.2.7" {
		t.Errorf("manifest version = %q, want 4.2.7", m.Version)
	}
	if majorFromString(m.Version) != Version4 {
		t.Errorf("major from %q = %v, want Version4", m.Version, majorFromString(m.Version))
	}
}

func TestMajorFromString(t *testing.T) {
	cases := map[string]MajorVersion{
		"3.10.12":   Version3,
		"4.2.7":     Version4,
		"5.0.0":     Version5,
		"5.4.6-rc1": Version5,
		"":          VersionUnknown,
		"junk":      VersionUnknown,
		"6.0.0":     VersionUnknown,
	}
	for in, want := range cases {
		if got := majorFromString(in); got != want {
			t.Errorf("majorFromString(%q) = %v, want %v", in, got, want)
		}
	}
}
