# Measure triage quality

Compare SecDepth alone, a one-shot model review, and the gated review on the same findings. Start with the mock benchmark to see how the scorer matches labels to results. You only need Python 3 and the `security-runtime` checkout.

## Run a no-model demo

Run these commands from the `security-runtime` checkout. The demo creates two saved scan bundles with synthetic evidence, one for a source finding and one for an artifact finding. It exercises the real acceptance gate with scripted model replies and makes zero live model calls.

```sh
benchmark_dir="$(mktemp -d)"
python3 -m benchmarks.demo --output "$benchmark_dir"
python3 -m json.tool "$benchmark_dir/comparison.json"
python3 benchmarks/score.py \
  "$benchmark_dir/labels.json" "$benchmark_dir/runs.json" \
  > "$benchmark_dir/comparison-rerun.json"
```

The demo writes `labels.json` with the expected verdicts, `runs.json` with the three sets of results, and `comparison.json` with the scores. The `source/` and `artifact/` directories each contain a saved report, checks, and a `triage.db` checkpoint. The last command runs the scorer again from the saved labels and results.

In the source case, the gate corrects a scripted verdict that conflicts with the saved checks. In the artifact case, the missing checks lead to `insufficient_evidence`. The gated result should match both expected verdicts. These scores describe the synthetic cases only. The model call counts represent scripted replies.

## Build a real benchmark

Keep a versioned set of findings that SecDepth flagged for review. Record the scan input and exact source revision or artifact digest for each finding. A reviewer must assign the expected verdict from the saved evidence before scoring. Keep cases used to tune prompts out of the published dataset.

Use the directory containing a scan's saved `report.json` and `checks.json`. Keep one directory per scan so a later run can reuse the same evidence.

Set `scan_dir` to a saved scan directory and list its flagged advisory IDs.

```sh
scan_dir=/path/to/saved-scan
python3 - "$scan_dir/report.json" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text())
for finding in report["vulnerabilities"]:
    if (finding.get("review") or {}).get("needed") is True:
        print(finding["id"])
PY
```

For the SecDepth-only result, record a flagged finding as `insufficient_evidence`. The flag means SecDepth left it open for review.

The existing gated worker runs from the repository root and uses one SQLite database per case. It invokes the authenticated personal `claude2` command, so it makes model calls. Capture its JSON output for each case and retain the scan directory and database with the benchmark records:

```sh
mkdir -p .state/benchmark-runs
finding_id=ADVISORY-ID
case_id=source-example-01
python3 main.py triage "$scan_dir" --provider claude2 \
  --finding "$finding_id" \
  --db ".state/benchmark-runs/$case_id.sqlite3" \
  > ".state/benchmark-runs/$case_id.gated.json"
```

Use a distinct case ID for each finding and scan pair, even when two scans report the same advisory. Read the captured `final.verdict` as `evidence_supports_report`, `evidence_conflicts_with_report`, or `insufficient_evidence`. Resume an interrupted worker with the same scan files and database.

The real benchmark still needs human labels and a one-shot runner. When recording both model approaches, use the same model and saved evidence for each case.

## Record and score results

Save `labels.json` with `schema_version: 1`, a nonblank `dataset_id`, and a `cases` array. Every case needs a unique `id`, a `target_kind` of `source` or `artifact`, and an `expected_verdict`.

Save `runs.json` with the same schema version and dataset ID. Put complete result arrays under `runs.secdepth`, `runs.one_shot`, and `runs.gated`. Every result must contain the case `id`, its `verdict`, integer `unsupported_claims`, `elapsed_ms`, and `model_calls`, plus `cost_usd` as a decimal string or `null`.

Run the scorer from the runtime checkout.

```sh
python3 benchmarks/score.py labels.json runs.json > comparison.json
```

Accuracy counts all labeled cases. Answered accuracy counts cases with a substantive verdict, so read it alongside the abstention count. Record elapsed time and model calls from each run. The scorer counts known prices separately so you can tell what the cost total covers.

## Related

- [Review loop design](review-loop-design.md)
