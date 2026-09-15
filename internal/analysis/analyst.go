// Package analysis wires the assessment into pipeline stages: profile parse,
// app identification, IPA intake, metadata extraction, static analysis,
// configuration analysis, API analysis, evidence collection, rule analysis
// and risk calculation. Env is the shared state handed to every rule.
// Analysis is read-only and offline; runtime assessment is not implemented
// and is refused with an honest error.
package analysis

import (
	"context"
	"sort"

	"github.com/QYVORA/qyvora-amanirenas/internal/errors"
	"github.com/QYVORA/qyvora-amanirenas/internal/events"
	"github.com/QYVORA/qyvora-amanirenas/internal/evidence"
	"github.com/QYVORA/qyvora-amanirenas/internal/mobile"
	"github.com/QYVORA/qyvora-amanirenas/internal/pipeline"
	"github.com/QYVORA/qyvora-amanirenas/internal/risk"
	"github.com/QYVORA/qyvora-amanirenas/internal/rules"
	"github.com/QYVORA/qyvora-amanirenas/pkg/models"
)

// Env is the environment passed to every rule during one assessment.
type Env struct {
	Profile *mobile.Profile
	Events  *events.Stream
	Store   *evidence.Store
	Config  map[string]any
}

// AddEvidence records an observation backing a finding, hashed and stored.
func (e *Env) AddEvidence(kind models.EvidenceKind, source, sourceID, target, data string) models.Evidence {
	ev := models.Evidence{
		Kind:     kind,
		Source:   source,
		SourceID: sourceID,
		Target:   target,
		Data:     data,
		State:    models.StateObserved,
	}
	if e.Store != nil {
		e.Store.Add(ev)
	}
	ev.Hash = models.HashContent(ev.Data)
	return ev
}

// Stages returns the full offline/simulation assessment pipeline.
func Stages(reg *rules.Registry, cfg map[string]any, maxEntries int) []pipeline.Stage {
	return []pipeline.Stage{
		{
			ID: "identification", Name: "Application identification",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				p, err := currentProfile(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.AppIdentified, map[string]any{
						"app_id": p.AppID, "bundle_id": p.BundleID, "source": string(p.Source),
						"version": p.Version, "build": p.Build,
					})
				}
				return nil
			},
		},
		{
			ID: "ipa", Name: "IPA intake",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				p, err := currentProfile(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.IPATaken, map[string]any{
						"entries": len(p.Entries), "architecture": p.Architecture,
						"signature": p.Signature,
					})
				}
				return nil
			},
		},
		{
			ID: "metadata", Name: "Metadata extraction",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				p, err := currentProfile(step)
				if err != nil {
					return err
				}
				step.Result.Assets = len(p.Entries)
				if step.Events != nil {
					step.Events.Info(events.MetadataExtracted, map[string]any{
						"assets": step.Result.Assets, "team_id": p.TeamID,
						"min_os": p.MinOS,
					})
				}
				return nil
			},
		},
		{
			ID: "static", Name: "Static analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				p, err := currentProfile(step)
				if err != nil {
					return err
				}
				secrets := len(mobile.HardcodedSecrets(p))
				webviews := len(mobile.LegacyWebViews(p))
				crypto := len(mobile.WeakCrypto(p))
				if step.Events != nil {
					step.Events.Info(events.StaticAnalyzed, map[string]any{
						"secrets": secrets, "webviews": webviews, "weak_crypto": crypto,
					})
				}
				return nil
			},
		},
		{
			ID: "config", Name: "Configuration analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				p, err := currentProfile(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.ConfigAnalyzed, map[string]any{
						"arbitrary_loads": p.Config.ArbitraryLoads,
						"http_loads":      len(p.Config.HTTPLoads),
						"backup_enabled":  !p.Config.DisablesBackup,
						"debug_enabled":   p.Config.DebugEnabled,
					})
				}
				return nil
			},
		},
		{
			ID: "api", Name: "API analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				p, err := currentProfile(step)
				if err != nil {
					return err
				}
				insecure := len(mobile.InsecureTransport(p))
				unpinned := len(mobile.MissingPinning(p))
				if step.Events != nil {
					step.Events.Info(events.APIAnalyzed, map[string]any{
						"endpoints": len(p.APIEndpoints), "insecure": insecure,
						"unpinned": unpinned,
					})
				}
				return nil
			},
		},
		{
			ID: "evidence", Name: "Evidence collection",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				p, err := currentProfile(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.EvidenceCollection, map[string]any{
						"artifacts": len(p.Artifacts), "frameworks": len(p.Frameworks),
						"permissions": len(p.Permissions),
					})
				}
				return nil
			},
		},
		{
			ID: "analysis", Name: "Rule analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				if reg == nil {
					return nil
				}
				p, err := currentProfile(step)
				if err != nil {
					return err
				}
				env := &Env{
					Profile: p,
					Events:  step.Events,
					Store:   step.Evidence,
					Config:  cfg,
				}
				sink := rules.NewSink()
				if err := reg.RunProfile(ctx, env, sink, profileOf(cfg)); err != nil {
					return err
				}
				for _, f := range sink.List() {
					if step.Target != nil {
						f.TargetID = step.Target.ID
					}
					step.Result.Findings = append(step.Result.Findings, *f)
					if step.Events != nil {
						step.Events.Info(events.FindingDiscovered, map[string]any{
							"rule_id": f.RuleID, "title": f.Title, "severity": string(f.Severity),
							"objects": f.Objects,
						})
					}
				}
				return nil
			},
		},
		{
			ID: "risk", Name: "Risk calculation",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				var assessor risk.Assessor
				score, level := assessor.Assess(ctx, headings(step.Result.Findings))
				step.Result.Score = score
				step.Result.Level = level
				step.Result.Evidence = step.Evidence.List()
				sort.Slice(step.Result.Evidence, func(i, j int) bool {
					return step.Result.Evidence[i].Hash < step.Result.Evidence[j].Hash
				})
				if step.Events != nil {
					step.Events.Info(events.RiskCalculated, map[string]any{
						"score": score, "level": level, "findings": len(step.Result.Findings),
					})
				}
				return nil
			},
		},
	}
}

func headings(fs []models.Finding) []*models.Finding {
	out := make([]*models.Finding, len(fs))
	for i := range fs {
		out[i] = &fs[i]
	}
	return out
}

func currentProfile(step *pipeline.Step) (*mobile.Profile, error) {
	if step == nil || step.Target == nil {
		return nil, errors.NewExitError(1, "assessment requires a profile or simulation target")
	}
	v, err := step.Cached("input:mobile", func() (any, error) {
		if step.Sim {
			return mobile.Simulate(mobile.SimulationOptions{}), nil
		}
		if step.Target.Type != models.TargetSnapshot {
			return nil, errors.NewExitError(1, "unsupported target: runtime assessment and live device acquisition are not implemented; provide a profile file")
		}
		p, err := mobile.LoadFile(step.Target.Value)
		if err != nil {
			return nil, errors.WrapExitError(1, "loading profile", err)
		}
		return p, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*mobile.Profile), nil
}

// profileOf returns the named assessment profile, defaulting to standard
// when the configuration does not select one.
func profileOf(cfg map[string]any) string {
	if p, ok := cfg["profile"].(string); ok && p != "" {
		return p
	}
	// No profile selected falls through to the full rule set so pipeline
	// invocations without an explicit profile behave exactly as before the
	// profile filter existed. The CLI always resolves an explicit profile.
	return ""
}
