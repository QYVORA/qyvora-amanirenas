# assess.qs — a runnable example of the shared QYVORA scripting engine driving
# amanirenas's offline iOS/mobile analysis pipeline.
#
#     amanirenas script run examples/assess.qs
#
# amanirenas is offline and deterministic, so this needs no target setup: with
# no app profile configured the binding runs the built-in simulation.

# Select the deterministic simulation (the default when no target is set).
set assess.sim -> "true"

# Run the full analysis pipeline. Capability ids such as "mobile.static" run the
# pipeline only up to and including that stage.
run assess

# Read live properties from the completed run via $(...).
echo -> "target   = $(target.name)"
echo -> "assets   = $(result.assets)"
echo -> "findings = $(result.findings)"
echo -> "score    = $(result.score) ($(result.level))"

# Show capability metadata and write a Markdown report artifact.
show mobile.static
report -> "amanirenas-report"

echo -> "done"
