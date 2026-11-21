# Monitor a target

The runtime keeps a history of scans for a source checkout or release artifact. You can compare two revisions to see which findings changed or scan the same revision again after new advisories appear. SecDepth writes the scan report and marks findings that need review. When you scan a compiled artifact, SecDepth calls secpeel to identify what shipped.

## Run a scan

Use Python 3 on macOS or Linux. Put the `secdepth` and `secpeel` checkouts next to `security-runtime/`. Choose a trusted local checkout or artifact, and keep the state directory outside the target you scan.

From `security-runtime/`, supply a Git commit SHA for a source scan.

```sh
python3 runtime.py --state .state run /path/to/checkout \
  --stream project-main --revision "$COMMIT_SHA" --trigger push
```

For a release, pass the built archive or executable and use its digest as the revision.

```sh
python3 runtime.py --state .state run /path/to/release.tar.gz \
  --stream project-linux-release --revision "$ARTIFACT_DIGEST" --trigger release
```

A stream is the scan history for one target. Give each branch, pull request, or release artifact variant its own stream. You supply the revision, so check that the local input matches it.

If the last successful scan was complete, an event with the same trigger and revision reuses that result. Scheduled runs, including `watch`, always scan again.

## Run periodically

`watch` starts a scan immediately, waits the configured interval after it finishes, then scans the same local path again. Stop it with Ctrl-C. Use `run --trigger scheduled` to let an operating-system scheduler or CI own the cadence.

```sh
python3 runtime.py --state .state watch /path/to/checkout \
  --stream project-main --interval 3600
```

A mutable checkout can change between scans. For reproducible reports, give each run an immutable checkout or artifact. Scheduled runs are useful even for an unchanged artifact because the advisory data can change.

## Read the result

Each attempt emits a JSON summary on stdout. Use its `run_id` to find the summary, scan log and available reports in `STATE/STREAM/runs/RUN_ID/`. A failed scan leaves the scan history available for the next run.

To identify new or changed findings, the runtime looks at the latest successful report and uses the last complete report to fill gaps in that comparison. It reports a finding as missing only when both the current scan and the baseline are complete. The runtime marks scans as partial if they have coverage gaps, advisory lookup gaps, or offline advisory data.

A missing finding describes a difference from the baseline. Verify the reason in the reports before treating it as remediation.

## Connect CI or Kubernetes

If you use another CI service, start with one repository and call `runtime.py run` from a job. For a push or merge request, pass the checkout for the exact commit and set the trigger to `push` or `merge-request`. For a release, pass the artifact from the build job. Keep the runtime state between jobs so it can compare findings, and save the JSON and HTML reports as CI artifacts.

GitLab supports rules for push, merge request, tag and scheduled pipelines. [GitLab job rules](https://docs.gitlab.com/ci/jobs/job_rules/)

If scans start competing for worker resources, package the runner and scanners in an image and execute each scan as a Kubernetes Job. A CronJob can start periodic runs. Keep reports and comparison state outside the pods. If duplicate jobs can run, use a store with transactional coordination and deduplicate by event identity. [Kubernetes Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/) · [Kubernetes CronJobs](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)

floop can review a completed report against explicit criteria, such as whether every coverage gap is explained or which conditional findings need human review. Running that review automatically requires a host that provides worker session controls and evidence. [floop usage](https://github.com/kobaltoxid/floop#use)

See the [review loop design](review-loop-design.md) for how scans feed model triage and what the unattended loop adds.

## Run on GitHub Actions

Add a workflow under `.github/workflows/` in the repository you want to scan. Set `ecosystem` to `npm` for a repository with a root `package.json` and npm lockfile, or `go` for one with a root `go.mod` and `go.sum`.

Replace `RUNTIME_COMMIT_SHA` with the full commit SHA of the security-runtime version you want to run.

```yaml
name: SecDepth dependency scan
on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    uses: kobaltoxid/security-runtime/.github/workflows/scan.yml@RUNTIME_COMMIT_SHA
    with:
      ecosystem: npm
```

The shared workflow scans the exact commit at the head of the pull request without installing dependencies. If the scanner fails, GitHub marks the job as failed. Open **Artifacts** in the calling repository's workflow run to read the scan log or inspect the reports for advisory matches and coverage gaps.
