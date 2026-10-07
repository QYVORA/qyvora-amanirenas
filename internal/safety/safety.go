// Package safety implements the architectural safety model of amanirenas.
//
// Every operation carries metadata describing its class, risk, authorization
// requirement, whether it changes remote state, and whether it is reversible.
// Mobile application analysis is read-only and offline by default: IPA and
// profile analysis need no authorization and never contact a device or store.
// Runtime assessment and live device acquisition are not implemented and are
// refused with an honest error rather than faked — no executing app code.
package safety

import "github.com/QYVORA/qyvora-amanirenas/pkg/models"

// Class identifies a family of assessment operation.
type Class string

const (
	ClassDiscovery  Class = "discovery"
	ClassAnalysis   Class = "analysis"
	ClassLiveDevice Class = "live-device"
)

// OperationMetadata describes one operation's safety contract.
type OperationMetadata struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Description  string              `json:"description"`
	Class        Class               `json:"class"`
	Risk         models.RiskLevel    `json:"risk"`
	NoiseLevel   models.NoiseLevel   `json:"noise_level"`
	TargetType   string              `json:"target_type"`
	AuthRequired bool                `json:"authorization_required"`
	Confirm      bool                `json:"confirmation_required"`
	ChangesState bool                `json:"changes_state"`
	Reversible   bool                `json:"reversible"`
}

// Known operations.
var (
	// OpProfileParse analyzes an offline app profile. Read-only, no auth.
	OpProfileParse = OperationMetadata{
		ID: "amanirenas.profile.parse", Name: "app profile snapshot analysis",
		Description: "Parse and analyze an offline app/profile snapshot file.",
		Class:       ClassDiscovery, Risk: models.RiskS1, NoiseLevel: models.NoiseLevelPassive, TargetType: "profile",
		AuthRequired: false, Confirm: false, ChangesState: false, Reversible: true,
	}
	// OpAnalyze runs the analysis pipeline; it never executes app code.
	OpAnalyze = OperationMetadata{
		ID: "amanirenas.analyze", Name: "mobile application analysis",
		Description: "Run metadata, static, configuration and API analysis over the profile.",
		Class:       ClassAnalysis, Risk: models.RiskS1, NoiseLevel: models.NoiseLevelPassive, TargetType: "any",
		AuthRequired: false, Confirm: false, ChangesState: false, Reversible: true,
	}
	// OpLiveDevice would attach to a physical device. Not implemented.
	OpLiveDevice = OperationMetadata{
		ID: "amanirenas.live.device", Name: "live device acquisition",
		Description: "Acquire runtime state from a physical iOS device (NOT IMPLEMENTED).",
		Class:       ClassLiveDevice, Risk: models.RiskS2, NoiseLevel: models.NoiseLevelModerate, TargetType: "device",
		AuthRequired: true, Confirm: true, ChangesState: false, Reversible: true,
	}
)

// Implemented reports whether an operation actually exists in this build.
// Runtime assessment and live device acquisition are deliberately not
// implemented; calling them must produce an honest error rather than pretend
// capability.
func (op OperationMetadata) Implemented() bool {
	return op.ID != OpLiveDevice.ID
}

// RequiresAuthorization reports whether an operation only runs on an
// authorized target.
func (op OperationMetadata) RequiresAuthorization() bool { return op.AuthRequired }
