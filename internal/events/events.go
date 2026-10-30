// Package events implements the shared QYVORA JSONL event envelope. Every
// emitted line is one JSON object:
//
//	{"schema_version":"1.0","timestamp":"...","execution_id":"...",
//	 "framework":"amanirenas","level":"info","event":"stage.completed","data":{}}
//
// Consumers key on event names, never on terminal output.
package events

import (
	"io"

	shared "github.com/QYVORA/qyvora-events"
)

// SchemaVersion is the event schema version every event carries.
const SchemaVersion = shared.SchemaVersion

// Shared, ecosystem-wide verbs plus amanirenas's cloud-specific verbs, shaped
// "category.thing.state" so consumers can route on prefix.
const (
	ScanStarted       = "scan.started"
	ScanCompleted     = "scan.completed"
	StageStarted      = "stage.started"
	StageCompleted    = "stage.completed"
	FindingDiscovered = "finding.discovered"
	EvidenceCollected = "evidence.collected"
	Warning           = "warning"
	Error             = "error"
	ReportGenerated   = "report.generated"

	AppIdentified      = "app.identified"
	IPATaken           = "ipa.intaked"
	MetadataExtracted  = "metadata.extracted"
	StaticAnalyzed     = "static.analyzed"
	ConfigAnalyzed     = "config.analyzed"
	APIAnalyzed        = "api.analyzed"
	RuntimeAssessed    = "runtime.assessed"
	EvidenceCollection = "evidence.collection"
	RiskCalculated     = "risk.calculated"
)

// Level values for the envelope's level field.
const (
	LevelInfo    = shared.LevelInfo
	LevelWarning = shared.LevelWarning
	LevelError   = shared.LevelError
)

type Event = shared.Event
type Stream = shared.Stream

// NewStream returns a stream bound to amanirenas.
func NewStream(w io.Writer) *Stream { return shared.NewStream(w, "amanirenas") }
