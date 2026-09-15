package mobile_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-amanirenas/internal/mobile"
)

func TestParseSourceRejectsUnknown(t *testing.T) {
	if mobile.ParseSource("pcap") != "" {
		t.Error("unknown source should parse to empty")
	}
}

func TestLoadRejectsUnsupportedSchema(t *testing.T) {
	_, err := mobile.Load(strings.NewReader(`{"schema":"qyvora.imhotep.snapshot.v1","app_id":"x","source":"ipa"}`))
	if err == nil {
		t.Fatal("expected schema rejection")
	}
}

func TestLoadRejectsMissingSource(t *testing.T) {
	_, err := mobile.Load(strings.NewReader(`{"schema":"qyvora.amanirenas.app.v1","app_id":"x"}`))
	if err == nil {
		t.Fatal("expected missing-source rejection")
	}
}

func TestSimulateIsDeterministic(t *testing.T) {
	a := mobile.Simulate(mobile.SimulationOptions{})
	b := mobile.Simulate(mobile.SimulationOptions{})
	ja, _ := mobile.Marshal(a)
	jb, _ := mobile.Marshal(b)
	if string(ja) != string(jb) {
		t.Error("simulation is not deterministic")
	}
}

func TestSimulateSurface(t *testing.T) {
	p := mobile.Simulate(mobile.SimulationOptions{})
	if p.Schema != "qyvora.amanirenas.app.v1" {
		t.Errorf("schema = %s", p.Schema)
	}
	if len(p.Entries) < 3 {
		t.Errorf("expected multiple IPA entries, got %d", len(p.Entries))
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"AKIA", "password>", "token=", "BEGIN RSA"} {
		if strings.Contains(string(data), needle) {
			t.Errorf("model embeds a raw secret-like value %q", needle)
		}
	}
	if len(mobile.HardcodedSecrets(p)) == 0 {
		t.Error("simulation should contain hardcoded-secret artifacts")
	}
}

func TestInsecureTransportAndPinning(t *testing.T) {
	p := mobile.Simulate(mobile.SimulationOptions{})
	if len(mobile.InsecureTransport(p)) == 0 {
		t.Error("expected insecure HTTP endpoints")
	}
	if len(mobile.MissingPinning(p)) == 0 {
		t.Error("expected missing-pinning endpoints")
	}
}

func TestStaticArtifacts(t *testing.T) {
	p := mobile.Simulate(mobile.SimulationOptions{})
	if len(mobile.LegacyWebViews(p)) == 0 {
		t.Error("expected a webview artifact")
	}
	if len(mobile.WeakCrypto(p)) < 2 {
		t.Errorf("expected weak-crypto artifacts, got %d", len(mobile.WeakCrypto(p)))
	}
	if len(mobile.DataStorage(p)) == 0 {
		t.Error("expected data-storage artifacts")
	}
	if len(mobile.ClipboardAccess(p)) == 0 {
		t.Error("expected clipboard artifact")
	}
}

func TestSensitivePermissions(t *testing.T) {
	p := mobile.Simulate(mobile.SimulationOptions{})
	out := mobile.SensitivePermissions(p)
	if len(out) == 0 {
		t.Error("camera permission has no purpose string and should be flagged")
	}
}

func TestPlatformFlags(t *testing.T) {
	p := mobile.Simulate(mobile.SimulationOptions{})
	if !mobile.LowMinimumOS(p) {
		t.Error("min OS 12.0 should be flagged as outdated")
	}
	if !mobile.AdHocSigning(p) {
		t.Error("ad-hoc signing should be flagged")
	}
	if !mobile.MissingJailbreakDetection(p) {
		t.Error("no jailbreak capability should be flagged")
	}
}

func TestValidate(t *testing.T) {
	if problems := mobile.Simulate(mobile.SimulationOptions{}).Validate(); len(problems) > 0 {
		t.Errorf("simulation should validate clean: %v", problems)
	}
	p := &mobile.Profile{Schema: mobile.SchemaVersion}
	if problems := p.Validate(); len(problems) == 0 {
		t.Error("empty profile should report problems")
	}
}

func TestSecretsCarryOnlyFingerprints(t *testing.T) {
	p := mobile.Simulate(mobile.SimulationOptions{})
	for _, a := range mobile.HardcodedSecrets(p) {
		if !strings.HasPrefix(a.Fingerprint, "fnv1a:") {
			t.Errorf("secret artifact %s missing fingerprint", a.ID)
		}
		if strings.Contains(a.Detail, "=") && strings.Contains(a.Detail, "0123SK") {
			t.Errorf("secret artifact %s leaks a value", a.ID)
		}
	}
}

func TestCounts(t *testing.T) {
	p := mobile.Simulate(mobile.SimulationOptions{})
	c := p.Counts()
	if c.Entries != len(p.Entries) || c.Artifacts != len(p.Artifacts) {
		t.Error("counts mismatch")
	}
}
