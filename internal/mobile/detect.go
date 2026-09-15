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

// MissingPinning returns TLS endpoints that do not pin certificates.
func MissingPinning(p *Profile) []APIEndpoint {
	var out []APIEndpoint
	for _, e := range p.APIEndpoints {
		if e.Scheme == "https" && !e.Pinned && strings.Contains(e.Discovered, "static") {
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

// LowMinimumOS reports profiles supporting old OS versions lacking modern
// platform security features.
func LowMinimumOS(p *Profile) bool {
	return p.MinOS != "" && strings.HasPrefix(p.MinOS, "1")
}

// AdHocSigning reports profiles not distributed through a verified App Store
// channel.
func AdHocSigning(p *Profile) bool {
	return p.Signature != "" && p.Signature != "app-store" && p.Signature != "enterprise"
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
