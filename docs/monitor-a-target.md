# Monitor a target

Use the runtime to scan a local source checkout or release artifact and retain the reports across runs. It calls secdepth's `scan.py`, which calls secpeel for artifact files. The runtime schedules scans and compares results. Findings flagged for review stay attached to the report.

## Run a scan

Use Python 3 on macOS or Linux with sibling `secdepth` and `secpeel` checkouts. Start with a trusted local checkout or artifact. Keep the state directory outside the scanned checkout.

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

The stream identifies the history being compared. Use a stream per branch or merge request and a separate stream for each release artifact variant. The revision is caller-supplied metadata, so make sure the local input matches it. When the last successful scan was complete, a repeated event with the same trigger and revision reuses that result. Scheduled runs, including `watch`, always scan again.

## Run periodically

`watch` starts a scan immediately, waits the configured interval after it finishes, then scans the same local path again. Stop it with Ctrl-C. Use `run --trigger scheduled` to let an operating-system scheduler or CI own the cadence.

```sh
python3 runtime.py --state .state watch /path/to/checkout \
  --stream project-main --interval 3600
```

A mutable checkout can change between scans. For reproducible reports, give each run an immutable checkout or artifact. Scheduled runs are useful even for an unchanged artifact because the advisory data can change.

## Read the result

Each attempt emits a JSON summary on stdout. Use its `run_id` to find the summary, scan log and available reports in `STATE/STREAM/runs/RUN_ID/`. A failed scan leaves the scan history available for the next run.

New and changed findings use the latest successful report, with the last complete report filling gaps in that comparison. Missing findings require both a complete current scan and a complete baseline. The runtime marks scans with coverage gaps, advisory lookup gaps or offline advisory data as partial.

A missing finding describes a difference from the baseline. Verify the reason in the reports before treating it as remediation.

## Connect CI or Kubernetes

Start with one repository and use the same `run` command in a CI job. For a push or merge request, hand over the exact commit checkout and label the trigger `push` or `merge-request`. For a release, hand over the output of the existing build job. Retain the runtime state between jobs and publish the JSON and HTML as CI artifacts.

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

The shared workflow scans the exact PR head without installing dependencies. Find the JSON and HTML reports, scan log, and run metadata under **Artifacts** in the calling repository's workflow run. A failed scan fails the job. Review advisory matches and coverage gaps in the artifacts.
