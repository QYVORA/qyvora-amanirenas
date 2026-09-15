// Package builtin registers the amanirenas rule set. Every rule reads only the
// provided analysis Env — the mobile profile — and produces machine-readable
// findings with attached evidence. Rules are static-only; nothing executes the
// app, and discovered secrets travel only as fingerprints.
package builtin

import (
	"context"
	"strings"

	"github.com/QYVORA/qyvora-amanirenas/internal/analysis"
	"github.com/QYVORA/qyvora-amanirenas/internal/events"
	"github.com/QYVORA/qyvora-amanirenas/internal/mobile"
	"github.com/QYVORA/qyvora-amanirenas/internal/rules"
	"github.com/QYVORA/qyvora-amanirenas/pkg/models"
)

// All returns the rules implicit in a stock assessment.
func All() []rules.Rule {
	return []rules.Rule{
		&hardcodedSecret{},
		&insecureTransport{},
		&missingPinning{},
		&legacyWebView{},
		&weakCrypto{},
		&insecureStorage{},
		&clipboardLeak{},
		&verboseLogging{},
		&excessivePermissions{},
		&lowMinimumOS{},
		&adhocSigning{},
		&missingTamper{},
	}
}

// metadata assembles a rule Meta with sane defaults for this rule set.
func metadata(id, name, category, description, recommendation string, sev models.Severity) rules.Meta {
	return rules.Meta{
		ID:                id,
		Name:              name,
		Category:          category,
		Description:       description,
		DefaultSeverity:   sev,
		DefaultConfidence: models.ConfidenceObserved,
		Recommendation:    recommendation,
	}
}

// newFinding fills the derived fields of a finding uniformly.
func newFinding(m rules.Meta, env *analysis.Env, objects []string, attrs map[string]string, ev ...models.Evidence) *models.Finding {
	return &models.Finding{
		RuleID:         m.ID,
		Title:          m.Name,
		Category:       m.Category,
		Description:    m.Description,
		Recommendation: m.Recommendation,
		Severity:       m.DefaultSeverity,
		Confidence:     m.DefaultConfidence,
		Status:         models.StatusDetected,
		State:          models.StateObserved,
		Objects:        objects,
		Attributes:     attrs,
		Evidence:       ev,
		Timestamp:      models.Now(),
	}
}

type hardcodedSecret struct{}

func (r *hardcodedSecret) Meta() rules.Meta {
	return metadata("AMN-001", "Hardcoded secret in app", "secrets",
		"Secret material such as API tokens or passwords is embedded in the "+
			"application bundle. Values are redacted; only fingerprints are shown.",
		"Move every secret to the keychain or a server-side service, rotate the "+
			"exposed values, and add secret scanning to the build pipeline.",
		models.SeverityCritical)
}

func (r *hardcodedSecret) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range mobile.HardcodedSecrets(env.Profile) {
		ev := env.AddEvidence(models.EvidenceArtifact, "static", a.ID,
			a.File, "hardcoded secret present (value redacted)")
		if env.Events != nil {
			env.Events.Info(events.StaticAnalyzed, map[string]any{
				"artifact": a.ID, "kind": a.Kind, "redacted": true,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"file": a.File, "fingerprint": a.Fingerprint, "redacted": "true"}, ev))
	}
	return nil
}

type insecureTransport struct{}

func (r *insecureTransport) Meta() rules.Meta {
	return metadata("AMN-002", "Insecure transport", "transport",
		"Endpoints or ATS exceptions allow cleartext HTTP traffic, letting an "+
			"attacker intercept data in transit.",
		"Remove cleartext HTTP hosts, enforce HTTPS with ATS, and migrate any "+
			"legacy endpoints to TLS.",
		models.SeverityCritical)
}

func (r *insecureTransport) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	seen := map[string]bool{}
	for _, e := range mobile.InsecureTransport(env.Profile) {
		key := e.Scheme + "://" + e.Host
		if seen[key] {
			continue
		}
		seen[key] = true
		ev := env.AddEvidence(models.EvidenceObservation, "api", e.Host,
			e.Discovered, "endpoint reachable over plaintext HTTP")
		if env.Events != nil {
			env.Events.Info(events.APIAnalyzed, map[string]any{
				"host": e.Host, "scheme": e.Scheme, "insecure": true,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"endpoint:" + e.Host},
			map[string]string{"host": e.Host, "scheme": e.Scheme, "note": e.Note}, ev))
	}
	return nil
}

type missingPinning struct{}

func (r *missingPinning) Meta() rules.Meta {
	return metadata("AMN-003", "Missing certificate pinning", "transport",
		"TLS endpoints that carry the app's sensitive traffic do not pin "+
			"certificates, widening exposure to malicious CAs.",
		"Pin production API certificates with backup pins and rotate on schedule.",
		models.SeverityMedium)
}

func (r *missingPinning) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, e := range mobile.MissingPinning(env.Profile) {
		ev := env.AddEvidence(models.EvidenceObservation, "api", e.Host,
			e.Discovered, "TLS endpoint without certificate pinning")
		sink.Add(newFinding(r.Meta(), env, []string{"endpoint:" + e.Host},
			map[string]string{"host": e.Host, "pinned": "no"}, ev))
	}
	return nil
}

type legacyWebView struct{}

func (r *legacyWebView) Meta() rules.Meta {
	return metadata("AMN-004", "Legacy WebView usage", "static",
		"The app uses the deprecated UIWebView surface, which lacks modern web "+
			"security and is no longer eligible for app review.",
		"Migrate to WKWebView with content-security and connectivity controls.",
		models.SeverityMedium)
}

func (r *legacyWebView) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range mobile.LegacyWebViews(env.Profile) {
		ev := env.AddEvidence(models.EvidenceArtifact, "static", a.ID,
			a.File, "deprecated webview surface in use")
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"file": a.File}, ev))
	}
	return nil
}

type weakCrypto struct{}

func (r *weakCrypto) Meta() rules.Meta {
	return metadata("AMN-005", "Weak cryptography", "crypto",
		"Code paths use broken or deprecated primitives (MD5, SHA1, DES) that "+
			"provide no real integrity protection.",
		"Replace weak primitives with modern authenticated algorithms (e.g. "+
			"SHA-256/AES-GCM) and validate with a static-analysis gate.",
		models.SeverityMedium)
}

func (r *weakCrypto) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range mobile.WeakCrypto(env.Profile) {
		ev := env.AddEvidence(models.EvidenceArtifact, "static", a.ID,
			a.File, "weak cryptographic primitive referenced")
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"file": a.File, "primitive": a.Fingerprint}, ev))
	}
	return nil
}

type insecureStorage struct{}

func (r *insecureStorage) Meta() rules.Meta {
	return metadata("AMN-006", "Insecure local data storage", "storage",
		"Sensitive data is persisted in unprotected containers (UserDefaults, "+
			"backup-enabled Documents), exposing it to theft or backup leakage.",
		"Store sensitive values in the keychain with access groups, exclude them "+
			"from backups, and gate with a storage policy.",
		models.SeverityHigh)
}

func (r *insecureStorage) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range mobile.DataStorage(env.Profile) {
		ev := env.AddEvidence(models.EvidenceArtifact, "static", a.ID,
			a.File, "sensitive data stored without protection")
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"file": a.File}, ev))
	}
	return nil
}

type clipboardLeak struct{}

func (r *clipboardLeak) Meta() rules.Meta {
	return metadata("AMN-007", "Sensitive data copied to clipboard", "data",
		"Payment or identity data is written to the shared pasteboard, where "+
			"other apps can read it.",
		"Remove pasteboard copies of sensitive data and add a clipboard guard.",
		models.SeverityMedium)
}

func (r *clipboardLeak) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range mobile.ClipboardAccess(env.Profile) {
		ev := env.AddEvidence(models.EvidenceArtifact, "static", a.ID,
			a.File, "pasteboard access with sensitive data")
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"file": a.File}, ev))
	}
	return nil
}

type verboseLogging struct{}

func (r *verboseLogging) Meta() rules.Meta {
	return metadata("AMN-008", "Sensitive data in logs", "data",
		"Request bodies or sensitive payloads are written to the system log.",
		"Strip sensitive fields before logging and gate logging behind debug builds.",
		models.SeverityLow)
}

func (r *verboseLogging) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range mobile.VerboseLogging(env.Profile) {
		ev := env.AddEvidence(models.EvidenceArtifact, "static", a.ID,
			a.File, "sensitive data logged")
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"file": a.File}, ev))
	}
	return nil
}

type excessivePermissions struct{}

func (r *excessivePermissions) Meta() rules.Meta {
	return metadata("AMN-009", "Excessive permissions", "permissions",
		"The app declares sensitive permissions whose purpose is not explained, "+
			"expanding the privacy blast radius.",
		"Remove unused permission declarations and document the purpose string for "+
			"every remaining one.",
		models.SeverityMedium)
}

func (r *excessivePermissions) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, perm := range mobile.SensitivePermissions(env.Profile) {
		ev := env.AddEvidence(models.EvidenceObservation, "permissions", perm.Name,
			perm.Name, "sensitive permission declared without usage rationale")
		if env.Events != nil {
			env.Events.Info(events.EvidenceCollection, map[string]any{
				"permission": perm.Name, "excessive": true,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"permission:" + perm.Name},
			map[string]string{"permission": perm.Name}, ev))
	}
	return nil
}

type lowMinimumOS struct{}

func (r *lowMinimumOS) Meta() rules.Meta {
	return metadata("AMN-010", "Outdated minimum OS version", "platform",
		"The app supports iOS versions that lack current platform security "+
			"controls and receive no modern hardening.",
		"Raise the deployment target to a supported OS and re-verify behavior.",
		models.SeverityLow)
}

func (r *lowMinimumOS) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	if !mobile.LowMinimumOS(env.Profile) {
		return nil
	}
	ev := env.AddEvidence(models.EvidenceObservation, "platform", env.Profile.MinOS,
		env.Profile.AppID, "minimum OS version predates modern security controls")
	sink.Add(newFinding(r.Meta(), env, []string{"profile:" + env.Profile.AppID},
		map[string]string{"min_os": env.Profile.MinOS}, ev))
	return nil
}

type adhocSigning struct{}

func (r *adhocSigning) Meta() rules.Meta {
	return metadata("AMN-011", "Ad-hoc signing without verified distribution", "signing",
		"The package is not signed through the App Store or verified enterprise "+
			"channel, weakening installation control and update authenticity.",
		"Publish through a verified channel and enforce team-identifier checks.",
		models.SeverityMedium)
}

func (r *adhocSigning) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	if !mobile.AdHocSigning(env.Profile) {
		return nil
	}
	ev := env.AddEvidence(models.EvidenceObservation, "signing", env.Profile.Signature,
		env.Profile.AppID, "package carries non-App-Store signing")
	sink.Add(newFinding(r.Meta(), env, []string{"profile:" + env.Profile.AppID},
		map[string]string{"signature": env.Profile.Signature, "team_id": env.Profile.TeamID}, ev))
	return nil
}

type missingTamper struct{}

func (r *missingTamper) Meta() rules.Meta {
	m := metadata("AMN-012", "No jailbreak or tamper detection", "armoring",
		"The app ships no jailbreak or tamper-detection capability, so payment and "+
			"identity surfaces run unarmed on modified devices.",
		"Add jailbreak detection with a fail-closed policy for sensitive flows, or "+
			"document the accepted risk.",
		models.SeverityMedium)
	// The absence of a capability is inferred from its non-observation, never
	// directly confirmed; confidence reflects that epistemic gap.
	m.DefaultConfidence = models.ConfidenceNotObserved
	return m
}

func (r *missingTamper) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	if !mobile.MissingJailbreakDetection(env.Profile) {
		return nil
	}
	ev := env.AddEvidence(models.EvidenceObservation, "armoring", env.Profile.BundleID,
		env.Profile.AppID, "no jailbreak/tamper detection present")
	sink.Add(newFinding(r.Meta(), env, []string{"profile:" + env.Profile.AppID},
		map[string]string{"bundle_id": env.Profile.BundleID}, ev))
	return nil
}

var _ = strings.TrimSpace // reserved for future string helpers
