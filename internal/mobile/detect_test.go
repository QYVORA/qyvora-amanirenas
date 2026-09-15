package mobile

import "testing"

func TestLowMinimumOSParsesMajorNumerically(t *testing.T) {
	cases := []struct {
		minOS string
		want  bool
	}{
		{"12.0", true},
		{"10.1", true},
		{"1.0", true},
		{"iOS 13.0.1", true},
		{"14", true},
		{"15.0", false},
		{"16.4", false},
		{"iOS 18.1.2", false},
		{"", false},
		{"latest", false},
	}
	for _, c := range cases {
		if got := LowMinimumOS(&Profile{MinOS: c.minOS}); got != c.want {
			t.Errorf("LowMinimumOS(%q) = %v, want %v", c.minOS, got, c.want)
		}
	}
}

func TestParseMajorVersion(t *testing.T) {
	if m, ok := parseMajorVersion("12.1"); !ok || m != 12 {
		t.Errorf("12.1 -> %d,%v", m, ok)
	}
	if m, ok := parseMajorVersion("iOS 16.0"); !ok || m != 16 {
		t.Errorf("iOS 16.0 -> %d,%v", m, ok)
	}
	if _, ok := parseMajorVersion(""); ok {
		t.Error("empty string must not parse")
	}
}

func TestAdHocSigningOnlyExplicitMarkers(t *testing.T) {
	cases := []struct {
		sig  string
		want bool
	}{
		{"ad-hoc", true},
		{"Ad Hoc", true},
		{"development", true},
		{"simulator", true},
		{"app-store", false},
		{"appstore", false},
		{"enterprise", false},
		{"testflight", false},
		{"", false},
		{"unknown-signature", false},
	}
	for _, c := range cases {
		if got := AdHocSigning(&Profile{Signature: c.sig}); got != c.want {
			t.Errorf("AdHocSigning(%q) = %v, want %v", c.sig, got, c.want)
		}
	}
}

func TestMissingPinningScopeIsAuthenticatedHTTPS(t *testing.T) {
	p := &Profile{APIEndpoints: []APIEndpoint{
		{Host: "a.example", Scheme: "https", Auth: "bearer", Pinned: false, Discovered: "static"},
		{Host: "b.example", Scheme: "https", Auth: "bearer", Pinned: false, Discovered: "config"},
		{Host: "c.example", Scheme: "https", Auth: "none", Pinned: false, Discovered: "static"},
		{Host: "d.example", Scheme: "https", Auth: "bearer", Pinned: true, Discovered: "static"},
		{Host: "e.example", Scheme: "http", Auth: "bearer", Pinned: false, Discovered: "static"},
	}}
	out := MissingPinning(p)
	if len(out) != 2 {
		t.Fatalf("MissingPinning = %d endpoints, want 2 (auth+pinned excluded)", len(out))
	}
	seen := map[string]bool{}
	for _, e := range out {
		seen[e.Host] = true
	}
	if !seen["a.example"] || !seen["b.example"] {
		t.Errorf("pinned and unauthenticated endpoints must not flag: %v", seen)
	}
}
