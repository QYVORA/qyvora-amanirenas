package mobile

// SimulationOptions tunes the deterministic demo profile.
type SimulationOptions struct{}

// Simulate returns a deterministic sample app profile exercising every
// analysis path: a hardcoded API token, plaintext HTTP endpoints with pinning
// absent, legacy WebView usage, weak cryptography, sensitive data persisted
// to non-protected storage, clipboard access, excessive permissions, a low
// minimum OS, ad-hoc signing and no jailbreak detection. no raw secret
// values; only fingerprints travel.
func Simulate(opts SimulationOptions) *Profile {
	p := &Profile{
		Schema:       SchemaVersion,
		AppID:        "com.acme.paysecure",
		Name:         "PaySecure",
		Source:       SourceIPA,
		Version:      "3.2.1",
		Build:        "118",
		BundleID:     "com.acme.paysecure",
		MinOS:        "12.0",
		Architecture: "arm64,armv7",
		TeamID:       "ABCDE12345",
		Signature:    "ad-hoc",
		Label:        "simulated app profile - fabricated sample application",
		Modified:     "2026-02-20T00:00:00Z",
		Entries: []Entry{
			{Path: "Payload/PaySecure.app/PaySecure", Size: 4121600},
			{Path: "Payload/PaySecure.app/Info.plist", Size: 8192},
			{Path: "Payload/PaySecure.app/embedded.mobileprovision", Size: 4096},
			{Path: "Payload/PaySecure.app/Frameworks/CorePayKit.framework", Size: 512000},
			{Path: "Payload/PaySecure.app/Assets/cert.pem", Size: 2048},
			{Path: "Payload/PaySecure.app/AppIcon60x60@2x.png", Size: 96},
			{Path: "Payload/PaySecure.app/Base.lproj/Main.storyboardc", Size: 20480},
		},
		Frameworks: []Framework{
			{Name: "UIKit", Arch: "arm64"},
			{Name: "WebKit", Arch: "arm64"},
			{Name: "Security", Arch: "arm64"},
			{Name: "CoreLocation", Arch: "arm64"},
			{Name: "CorePayKit", Arch: "armv7"},
		},
		Permissions: []Permission{
			{Name: "NSCameraUsageDescription", Usage: ""},
			{Name: "NSLocationWhenInUseUsageDescription", Usage: "show nearby merchants"},
			{Name: "NSMicrophoneUsageDescription", Usage: "voice capture for support"},
			{Name: "NSContactsUsageDescription", Usage: "sync payment contacts"},
		},
		Config: Config{
			ArbitraryLoadsHTTPS:     false,
			ArbitraryLoads:          false,
			HTTPLoads:               []string{"pay-api.acme-mobile.test", "cdn-track.acme.test"},
			LocalNetwork:            true,
			UsesNonSecureFrameworks: []string{"WebKit"},
			DisablesBackup:          false,
			DebugEnabled:            true,
			Jailbreak:               false,
		},
		APIEndpoints: []APIEndpoint{
			{Host: "api.acme-pay.test", Scheme: "https", Auth: "bearer", Pinned: true,
				Discovered: "config", Note: "pin configured in app"},
			{Host: "pay-api.acme-mobile.test", Scheme: "http", Auth: "none", Pinned: false,
				Discovered: "static", Note: "plaintext fallback host"},
			{Host: "cdn-track.acme.test", Scheme: "http", Auth: "none", Pinned: false,
				Discovered: "static", Note: "analytics endpoint without TLS"},
			{Host: "gateway.acme-pay.test", Scheme: "https", Auth: "bearer", Pinned: false,
				Discovered: "static", Note: "TLS only, no certificate pinning"},
		},
		Artifacts: []Artifact{
			{ID: "art-webview-1", Kind: "webview", File: "PaySecure/WebSupportViewController.m",
				Detail: "UIWebView initialized for in-app checkout"},
			{ID: "art-crypto-1", Kind: "insecure_crypto", File: "PaySecure/PayCrypto.m",
				Detail: "MD5 used for receipt checksum", Fingerprint: "md5:cfcd208495d565ef66e7dff9f98764da"},
			{ID: "art-crypto-2", Kind: "insecure_crypto", File: "PaySecure/TokenStore.swift",
				Detail: "SHA1 hashing for device fingerprint"},
			{ID: "art-secret-1", Kind: "hardcoded_secret", File: "PaySecure/Config.swift",
				Detail: "hardcoded API token (value redacted)", Fingerprint: "sha256:a1b2c3d4e5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8"},
			{ID: "art-secret-2", Kind: "hardcoded_secret", File: "PaySecure/SupportViewController.swift",
				Detail: "hardcoded support password (value redacted)", Fingerprint: "sha256:11223344556677889900aabbccddeeff1122334455667788"},
			{ID: "art-storage-1", Kind: "data_storage", File: "PaySecure/SessionStore.swift",
				Detail: "session token persisted in UserDefaults without protection"},
			{ID: "art-storage-2", Kind: "data_storage", File: "PaySecure/CacheManager.swift",
				Detail: "sensitive payload written to Documents with backup enabled"},
			{ID: "art-clipboard-1", Kind: "clipboard", File: "PaySecure/CardEntryViewController.swift",
				Detail: "card number copied to UIPasteboard"},
			{ID: "art-logging-1", Kind: "logging", File: "PaySecure/PayAPI.swift",
				Detail: "request bodies logged via NSLog"},
		},
		Risks: []RiskProfile{
			{ID: "risk-ats-1", Category: "ats", Count: 2,
				Detail: "App Transport Security allows cleartext HTTP hosts"},
			{ID: "risk-sign-1", Category: "signing", Count: 1,
				Detail: "package signed ad-hoc with no App Store distribution"},
		},
	}
	normalize(p)
	return p
}
