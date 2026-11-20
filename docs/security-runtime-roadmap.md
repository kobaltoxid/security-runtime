# Security runtime roadmap

Build an unattended loop that turns a change to source or a release artifact into a reviewable dependency security report. Start with one repository and one trigger. The first demo should show the runtime resuming after an interruption, rejecting an unsupported model claim, and comparing the final verdict with a one-shot review.

## What exists today

The local runtime accepts a checkout or artifact path, runs scans on demand or on a timer, and archives reports and finding deltas. SecDepth resolves source dependencies and matches known advisories. For compiled artifacts, it calls secpeel to identify what shipped and collect evidence. [Local run guide](monitor-a-target.md) · [SecDepth](https://github.com/kobaltoxid/secdepth) · [secpeel](https://github.com/kobaltoxid/secpeel)

floop defines how to check delegated work against acceptance criteria and request a bounded correction. The runtime will supply floop with the draft, evidence, and ability to request a revision. Ordinary runs will need no human input after the criteria are configured. [floop](https://github.com/kobaltoxid/floop)

## How the first loop should work

1. **Scan.** CI hands the runtime a source snapshot pinned to a commit SHA. For releases, a later adapter passes the build output with its digest. The runtime records the event identity and preserves the scanner outputs and coverage gaps.
2. **Review.** An existing hosted or local model reviews flagged findings through a small set of read-only tools. It receives the current finding and scanner evidence directly. This design uses no retrieval index or model training.
3. **Check.** The runtime validates the output schema, evidence references, and permitted tool calls. A floop-based review checks whether the evidence supports the verdict. If it fails, the runtime allows one bounded revision before marking the review inconclusive.
4. **Save.** Store run checkpoints, evidence references, verdicts, and model and policy versions in SQLite for the pilot. Keep the raw scanner report alongside the reviewed result. Resume from the last committed checkpoint after a restart.

The runtime owns tool permissions, time budgets, and stop conditions. Public pilot jobs use public source and advisory data. Keep reports from private inputs restricted and give the model access only to the current run's evidence. Any later write to a live system requires a runtime check that ties the approver, revision, destination, and exact payload to the recorded action.

## GitHub Projects backlog

| Order | Issue title | Done when |
| --- | --- | --- |
| 1 | Run SecDepth on one repository's PRs | A trusted CI job scans the exact PR commit and retains the report and coverage status. Event replay and scan failure are visible in the run record. |
| 2 | Own and resume the model triage loop | A standalone worker reviews one flagged finding with a ready model. Restarting after an interruption resumes from a checkpoint and produces one final result. |
| 3 | Apply floop acceptance criteria automatically | Fixtures exercise a supported verdict, an unsupported claim that gets corrected, and repeated failure that ends as inconclusive. Missing evidence cannot pass the gate. |
| 4 | Measure triage quality against a baseline | A versioned set of human-labeled source and artifact findings compares SecDepth alone, one-shot review, and the gated loop. Publish verdict accuracy, unsupported claims, abstentions, and per-run cost and time. |
| 5 | Add push, release, and scheduled triggers | Push scans record the commit SHA. Release scans record the artifact digest and secpeel evidence. Scheduled runs can surface new advisories for an unchanged target. Each stream retains its own history. |
| 6 | Gate a GitHub write in a test repository | A test PR comment waits for approval, a change to its destination or body invalidates the approval, and retrying a completed request leaves one comment. |

Score the three approaches on the same held-out cases. Use the same model and scanner evidence for both model variants. Report inconclusive cases alongside accuracy so the gate cannot appear to improve by withholding difficult verdicts.

## After the pilot

Add isolated regression fuzzing for owned code as a source of test and coverage evidence. Consider Kubernetes Jobs when the workload needs a separate worker pool or stronger isolation. For the pilot, use a CI runner with a state directory that persists across jobs.

Use GitHub Projects to track status, assignees, and PRs. Keep this design page for the scope and acceptance criteria. Link it from the board once it has a public repository URL.
