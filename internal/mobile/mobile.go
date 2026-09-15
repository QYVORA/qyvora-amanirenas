// Package mobile implements the iOS/mobile application snapshot model for
// amanirenas. A profile document is a read-only JSON model of one analyzed
// application or device: bundle metadata, IPA contents, signed code features,
// static-analysis artifacts, configuration posture and discovered API
// endpoints.
//
// The model supports offline IPA analysis. Runtime assessment is a separate
// capability and is not implemented; nothing here executes the app or claims
// live device behavior.
package mobile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SchemaVersion is the profile document schema this build reads and writes.
const SchemaVersion = "qyvora.amanirenas.app.v1"

// Source identifies where a profile came from.
type Source string

const (
	SourceIPA     Source = "ipa"
	SourceStore   Source = "store-catalog"
	SourceProfile Source = "config-profile"
	SourceDevice  Source = "device"
	SourceLive    Source = "live"
	SourceNone    Source = ""
)

// ParseSource normalizes a source name, returning None for unknown values.
func ParseSource(s string) Source {
	switch Source(strings.ToLower(strings.TrimSpace(s))) {
	case SourceIPA, SourceStore, SourceProfile:
		return Source(strings.ToLower(strings.TrimSpace(s)))
	case "device":
		return SourceDevice
	case "live":
		return SourceLive
	default:
		return SourceNone
	}
}

// Profile is the full offline analysis surface of one app or device.
type Profile struct {
	Schema       string        `json:"schema"`
	AppID        string        `json:"app_id"`
	Name         string        `json:"name"`
	Source       Source        `json:"source"`
	Version      string        `json:"version,omitempty"`
	Build        string        `json:"build,omitempty"`
	BundleID     string        `json:"bundle_id"`
	MinOS        string        `json:"min_os,omitempty"`
	Architecture string        `json:"architecture,omitempty"`
	TeamID       string        `json:"team_id,omitempty"`
	Signature    string        `json:"signature,omitempty"` // app-store/adhoc/development/free/profile
	Label        string        `json:"label,omitempty"`
	Modified     string        `json:"modified,omitempty"`
	Entries      []Entry       `json:"entries,omitempty"`
	Frameworks   []Framework   `json:"frameworks,omitempty"`
	Permissions  []Permission  `json:"permissions,omitempty"`
	Config       Config        `json:"config,omitempty"`
	APIEndpoints []APIEndpoint `json:"api_endpoints,omitempty"`
	Artifacts    []Artifact    `json:"artifacts,omitempty"`
	Risks        []RiskProfile `json:"risks,omitempty"`
}

// Entry is one file inside the IPA bundle.
type Entry struct {
	Path string `json:"path"`
	Size int    `json:"size"`
	Hash string `json:"hash,omitempty"`
}

// Framework is a linked framework or SDK.
type Framework struct {
	Name string `json:"name"`
	Arch string `json:"arch,omitempty"`
}

// Permission is a declared runtime permission.
type Permission struct {
	Name  string `json:"name"`
	Usage string `json:"usage,omitempty"`
}

// Config captures plist-level security posture.
type Config struct {
	ArbitraryLoads          bool     `json:"arbitrary_loads,omitempty"`
	ArbitraryLoadsHTTPS     bool     `json:"arbitrary_loads_https,omitempty"`
	HTTPLoads               []string `json:"http_loads,omitempty"`
	LocalNetwork            bool     `json:"local_network,omitempty"`
	UsesNonSecureFrameworks []string `json:"uses_non_secure_frameworks,omitempty"`
	DisablesBackup          bool     `json:"disables_backup,omitempty"`
	Jailbreak               bool     `json:"jailbreak,omitempty"`
	DebugEnabled            bool     `json:"debug_enabled,omitempty"`
}

// APIEndpoint is a host discovered via static or configuration analysis.
type APIEndpoint struct {
	Host       string `json:"host"`
	Scheme     string `json:"scheme,omitempty"` // https/http
	Auth       string `json:"auth,omitempty"`   // none/basic/bearer/certificate_pinning
	Pinned     bool   `json:"pinned,omitempty"`
	Path       string `json:"path,omitempty"`
	Discovered string `json:"discovered,omitempty"` // static/config/network
	Note       string `json:"note,omitempty"`
}

// Artifact is a static-analysis finding surface (strings, APIs, secrets).
// Any embedded secret is hashed/redacted; raw values are never stored.
type Artifact struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"` // webview/insecure_crypto/hardcoded_secret/data_storage/clipboard/logging/url_scheme
	File        string `json:"file,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// RiskProfile is a structured aggregate of one security risk bucket.
type RiskProfile struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Count    int    `json:"count"`
	Detail   string `json:"detail,omitempty"`
}

// Load parses a profile from r, rejecting documents that do not declare the
// profile schema.
func Load(r io.Reader) (*Profile, error) {
	var p Profile
	dec := json.NewDecoder(r)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parsing profile: %w", err)
	}
	if p.Schema != SchemaVersion {
		return nil, fmt.Errorf("unsupported profile schema %q (want %s)", p.Schema, SchemaVersion)
	}
	if p.Source = ParseSource(string(p.Source)); p.Source == SourceNone {
		return nil, fmt.Errorf("profile declares no supported source (ipa|store-catalog|config-profile)")
	}
	normalize(&p)
	return &p, nil
}

// LoadFile loads a profile from a file path.
func LoadFile(path string) (*Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return Load(f)
}

func normalize(p *Profile) {
	for i := range p.Entries {
		if p.Entries[i].Hash == "" {
			p.Entries[i].Hash = placeholderHash(p.Entries[i].Path)
		}
	}
	for i := range p.Artifacts {
		if p.Artifacts[i].Fingerprint == "" && p.Artifacts[i].Kind == "hardcoded_secret" {
			p.Artifacts[i].Fingerprint = placeholderHash(p.Artifacts[i].Detail)
		}
	}
}

func placeholderHash(s string) string {
	if s == "" {
		return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	return "sha256:" + shorthash(s)
}

func shorthash(s string) string {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x%016x", h, h^0x9e3779b97f4a7c15)
}

// Counts returns per-category inventory totals, used by reports.
type Counts struct {
	Entries     int `json:"entries"`
	Frameworks  int `json:"frameworks"`
	Permissions int `json:"permissions"`
	Endpoints   int `json:"api_endpoints"`
	Artifacts   int `json:"artifacts"`
	Risks       int `json:"risks"`
}

// Counts computes the inventory totals of a profile.
func (p *Profile) Counts() Counts {
	return Counts{
		Entries: len(p.Entries), Frameworks: len(p.Frameworks),
		Permissions: len(p.Permissions), Endpoints: len(p.APIEndpoints),
		Artifacts: len(p.Artifacts), Risks: len(p.Risks),
	}
}

// Validate runs structural sanity checks on a parsed profile.
func (p *Profile) Validate() []string {
	var problems []string
	if p.Schema != SchemaVersion {
		problems = append(problems, "missing profile schema version")
	}
	if p.BundleID == "" {
		problems = append(problems, "missing bundle identifier")
	}
	if len(p.Entries) == 0 {
		problems = append(problems, "profile holds no IPA entries; run `amanirenas profile` to generate a sample")
	}
	return problems
}

// Marshal renders a profile as indented JSON.
func Marshal(p *Profile) ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}
