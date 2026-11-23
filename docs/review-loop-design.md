# Review loop design

SecDepth can match a dependency to a known advisory while leaving open whether the affected code runs in the application. When SecDepth flags a finding like this for review, the runtime gives Claude the evidence from the scan and records a separate verdict. The maintainer can return to the original scan to see how the finding was reported.

## Goal and constraints

The goal is to scan changes to source code and release artifacts, review the evidence, and save a report a maintainer can inspect. Once the review criteria are configured, ordinary runs should need no human input. The current pull request pilot starts when a maintainer selects a completed scan.

- The runtime sets tool permissions and time limits and decides when a review ends.
- The model sees only the current run's evidence. The design uses no retrieval index or model training.
- Public pilot jobs use public source and advisory data. Reports from private inputs stay restricted.
- Any write to a live system needs a runtime check that ties the approver, revision, destination, and exact payload to the recorded action.

## How it works today

The scan and the review run separately. This allows GitHub Actions to report whether the scan completed and lets a maintainer request a review using the saved evidence.

![Scan reports feed the triage worker, which exchanges requests and actions with Claude and records a verdict in SQLite.](diagrams/scan-and-triage.svg)

Figure 1. Scan and triage path. Green: main path; dashed grey: model reply. See the [D2 source](diagrams/scan-and-triage.d2).

1. **Run the scan.** The reusable `scan.yml` workflow runs SecDepth on the exact pull request commit and saves its reports. For pushes, scheduled runs, and release builds, it runs the runtime and keeps each stream's history in the Actions cache. Locally, `python3 main.py scan` scans a checkout or artifact and compares findings across runs. SecDepth calls secpeel to examine compiled artifacts. [Monitor a target](monitor-a-target.md)
2. **Request a review.** A maintainer selects a completed scan. The hosted workflow verifies the pull request commit and saved artifact before the triage worker selects one flagged finding. Claude can ask the runtime for the recorded checks or affected components, then return a verdict.
3. **Check the evidence and verdict.** The runtime allows up to two evidence requests. It applies floop’s acceptance pattern by comparing the proposed verdict with the observed SecDepth checks for the selected finding. If the verdict misstates what those checks show, the runtime can ask for one correction using the same evidence. [floop](https://github.com/kobaltoxid/floop)
4. **Save the verdict.** The worker stores each step and the final verdict in SQLite. If the checks are insufficient or the correction still fails the gate, the worker records `insufficient_evidence`. The runtime identifies a run by its input, model, provider, and policy version. Repeating a review with the same inputs and database resumes it or returns the stored verdict. [Triage a finding](triage-a-finding.md)

## Planned additions

The [private project board](https://github.com/users/kobaltoxid/projects/1) tracks the order, status, and completion criteria for the remaining work.

- **Quality baseline.** Compare SecDepth alone, a one-shot review, and the gated loop on the same held-out, human-labeled findings. Report inconclusive cases beside accuracy. [Measure triage quality](measure-triage-quality.md)
- **Gated writes.** A GitHub write, such as a PR comment, waits for an approval that becomes invalid if the destination or body changes.

After the pilot, isolated regression fuzzing of code we own could add test and coverage evidence. A CI runner with persistent state is enough for the pilot. Kubernetes Jobs become useful when scans need a separate worker pool or stronger isolation.
