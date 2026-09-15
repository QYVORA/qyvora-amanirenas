package mobile

import (
	"strings"
)

// HardcodedSecrets returns the secret-bearing artifacts; only fingerprints
// travel, never values.
func HardcodedSecrets(p *Profile) []Artifact {
	var out []Artifact
	for _, a := range p.Artifacts {
		if a.Kind == "hardcoded_secret" {
			out = append(out, a)
		}
	}
	return out
}

// InsecureTransport returns endpoints using plaintext HTTP or missing TLS.
func InsecureTransport(p *Profile) []APIEndpoint {
	var out []APIEndpoint
	for _, e := range p.APIEndpoints {
		if e.Scheme == "http" {
			out = append(out, e)
		}
	}
	for _, h := range p.Config.HTTPLoads {
		out = append(out, APIEndpoint{Host: h, Scheme: "http", Auth: "none", Discovered: "config",
			Note: "cleartext HTTP load exception"})
	}
	return out
}

// MissingPinning returns TLS endpoints carrying authenticated traffic that do
// not pin certificates. Only endpoints using auth binding (bearer/basic) are
// considered sensitive enough to require pinning, and every discovery method
// (static or discovered later) is in scope.
func MissingPinning(p *Profile) []APIEndpoint {
	var out []APIEndpoint
	for _, e := range p.APIEndpoints {
		if e.Scheme == "https" && !e.Pinned && e.Auth != "" && !strings.EqualFold(e.Auth, "none") {
			out = append(out, e)
		}
	}
	return out
}

// LegacyWebViews returns webview artifacts still using the deprecated
// UIWebView surface.
func LegacyWebViews(p *Profile) []Artifact {
	var out []Artifact
	for _, a := range p.Artifacts {
		if a.Kind == "webview" {
			out = append(out, a)
		}
	}
	return out
}

// WeakCrypto returns artifacts using weak or broken cryptographic primitives.
func WeakCrypto(p *Profile) []Artifact {
	var out []Artifact
	for _, a := range p.Artifacts {
		if a.Kind == "insecure_crypto" {
			out = append(out, a)
		}
	}
	return out
}

// DataStorage returns artifacts storing sensitive data without protection.
func DataStorage(p *Profile) []Artifact {
	var out []Artifact
	for _, a := range p.Artifacts {
		if a.Kind == "data_storage" {
			out = append(out, a)
		}
	}
	return out
}

// ClipboardAccess returns artifacts touching the pasteboard.
func ClipboardAccess(p *Profile) []Artifact {
	var out []Artifact
	for _, a := range p.Artifacts {
		if a.Kind == "clipboard" {
			out = append(out, a)
		}
	}
	return out
}

// VerboseLogging returns artifacts logging sensitive data.
func VerboseLogging(p *Profile) []Artifact {
	var out []Artifact
	for _, a := range p.Artifacts {
		if a.Kind == "logging" {
			out = append(out, a)
		}
	}
	return out
}

// SensitivePermissions returns declared permissions that exceed a basic app
// need (contacts, microphone, location always, camera).
func SensitivePermissions(p *Profile) []Permission {
	sensitive := map[string]bool{
		"NSCameraUsageDescription":            true,
		"NSMicrophoneUsageDescription":        true,
		"NSContactsUsageDescription":          true,
		"NSLocationAlwaysUsageDescription":    true,
		"NSLocationWhenInUseUsageDescription": true,
	}
	var out []Permission
	for _, perm := range p.Permissions {
		if sensitive[perm.Name] && perm.Usage == "" {
			// no usage string makes an over-privileged claim
			out = append(out, perm)
		}
	}
	return out
}

// MinOSMajorThreshold is the oldest supported major OS version considered to
// carry modern platform security controls; majors strictly below are flagged.
const MinOSMajorThreshold = 15

// LowMinimumOS reports profiles supporting OS versions that lack current
// platform security features. The major version is parsed numerically from
// the declared string ("12.1", "iOS 13.0.1"), so "1.x" prefixes of any major
// like 10/11/12/13 no longer mis-evaluate as one.
func LowMinimumOS(p *Profile) bool {
	major, ok := parseMajorVersion(p.MinOS)
	if !ok {
		return false
	}
	return major < MinOSMajorThreshold
}

// parseMajorVersion extracts the leading numeric major from version strings.
func parseMajorVersion(s string) (int, bool) {
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			start = i
			break
		}
	}
	if start < 0 {
		return 0, false
	}
	end := start
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	major := 0
	for i := start; i < end; i++ {
		major = major*10 + int(s[i]-'0')
	}
	return major, true
}

// AdHocSigning reports profiles whose signing indicates an unverified ad-hoc
// or development distribution channel. Only explicit markers are treated as
// ad-hoc; unknown signature strings are not asserted one way or the other.
func AdHocSigning(p *Profile) bool {
	if p.Signature == "" {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(p.Signature))
	for _, verified := range []string{"app-store", "appstore", "store", "enterprise", "testflight"} {
		if strings.Contains(s, verified) {
			return false
		}
	}
	for _, adhoc := range []string{"ad-hoc", "adhoc", "ad hoc", "development", "simulator"} {
		if strings.Contains(s, adhoc) {
			return true
		}
	}
	return false
}

// MissingJailbreakDetection reports armed-surface when the app carries no
// jailbreak or tamper-detection capability.
func MissingJailbreakDetection(p *Profile) bool {
	for _, a := range p.Artifacts {
		if a.Kind == "jailbreak_detection" {
			return false
		}
	}
	return true
}

// WeakSecretStorage reports profiles that store secrets in backup-enabled
// , unencrypted containers.
func WeakSecretStorage(p *Profile) bool {
	return !p.Config.DisablesBackup || p.Config.DebugEnabled
}

// RuntimeUnavailable is a constant string used to refuse runtime claims. It is
// not an executable capability; runtime assessment is not implemented.
const RuntimeUnavailable = "runtime assessment is not implemented; analyze the IPA offline instead"
