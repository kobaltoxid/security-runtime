# Monitor a target

The runtime keeps a history of scans for a source checkout or release artifact. You can compare two revisions to see which findings changed or scan the same revision again after new advisories appear. SecDepth writes the scan report and marks findings that need review. When you scan a compiled artifact, SecDepth calls secpeel to identify what shipped.

## Run a scan

Use Python 3 on macOS or Linux. Put the `secdepth` and `secpeel` checkouts next to `security-runtime/`. Choose a trusted local checkout or artifact, and keep the state directory outside the target you scan.

From `security-runtime/`, supply a Git commit SHA for a source scan.

```sh
python3 main.py scan --state .state /path/to/checkout \
  --stream project-main --revision "$COMMIT_SHA" --trigger push
```

For a release, pass the built archive or executable and use its digest as the revision.

```sh
python3 main.py scan --state .state /path/to/release.tar.gz \
  --stream project-linux-release --revision "$ARTIFACT_DIGEST" --trigger release
```

A stream is the scan history for one target. Give each branch, pull request, or release artifact variant its own stream. You supply the revision, so check that the local input matches it.

If the last successful scan was complete, an event with the same trigger and revision reuses that result. Scheduled runs, including `watch`, always scan again.

## Run periodically

`watch` starts a scan immediately, waits the configured interval after it finishes, then scans the same local path again. Stop it with Ctrl-C. Use `scan --trigger scheduled` to let an operating-system scheduler or CI set the cadence.

```sh
python3 main.py watch --state .state /path/to/checkout \
  --stream project-main --interval 3600
```

A mutable checkout can change between scans. For reproducible reports, give each run an immutable checkout or artifact. Scheduled runs are useful even for an unchanged artifact because the advisory data can change.

## Read the result

Each attempt emits a JSON summary on stdout. Use its `run_id` to find the summary, scan log and available reports in `STATE/STREAM/runs/RUN_ID/`. A failed scan leaves the scan history available for the next run.

To identify new or changed findings, the runtime looks at the latest successful report and uses the last complete report to fill gaps in that comparison. It reports a finding as missing only when both the current scan and the baseline are complete. The runtime marks scans as partial if they have coverage gaps, advisory lookup gaps, or offline advisory data.

A missing finding describes a difference from the baseline. Verify the reason in the reports before treating it as remediation.

## Connect CI or Kubernetes

If you use another CI service, start with one repository and call `main.py scan` from a job. For a push or merge request, pass the checkout for the exact commit and set the trigger to `push` or `merge-request`. For a release, pass the artifact from the build job. Keep the runtime state between jobs so it can compare findings, and save the JSON and HTML reports as CI artifacts.

GitLab supports rules for push, merge request, tag and scheduled pipelines. [GitLab job rules](https://docs.gitlab.com/ci/jobs/job_rules/)

If scans start competing for worker resources, package the runner and scanners in an image and execute each scan as a Kubernetes Job. A CronJob can start periodic runs. Keep reports and comparison state outside the pods. If duplicate jobs can run, use a store with transactional coordination and deduplicate by event identity. [Kubernetes Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/) · [Kubernetes CronJobs](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)

floop can review a completed report against explicit criteria, such as whether every coverage gap is explained or which conditional findings need human review. Running that review automatically requires a host that provides worker session controls and evidence. [floop usage](https://github.com/kobaltoxid/floop#use)

See the [review loop design](review-loop-design.md) for how scans feed model triage and what the unattended loop adds.

## Run on GitHub Actions

Call the shared workflow from a workflow under `.github/workflows/` in the repository you want to scan. Replace `RUNTIME_COMMIT_SHA` with the full commit SHA of the security-runtime version you want to run. Set `ecosystem` to `npm` for a repository with a root `package.json` and npm lockfile, or `go` for one with a root `go.mod` and `go.sum`.

### Scan pull requests

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

The shared workflow scans the exact commit at the head of the pull request without installing dependencies. If the scanner fails, GitHub marks the job as failed. Open **Artifacts** in the calling repository's workflow run to read the scan log or inspect the reports for advisory matches and coverage gaps. Pull request scans keep no history between runs.

### Scan pushes and scheduled runs

Add `push`, `schedule`, or `workflow_dispatch` to the same caller. These events run the shared workflow's history job instead of the pull request job.

```yaml
on:
  push:
    branches: [main]
  schedule:
    - cron: "17 6 * * 1"
```

The history job scans the commit that triggered the run and records its SHA as the revision. Pushes and scheduled runs on a branch share the stream `branch-<branch>`. A scheduled run therefore compares the unchanged commit with the previous scan and reports advisories published since then as new findings. A repeated push of a commit that already has a complete scan reuses that result.

### Scan a release build

Build the release in an earlier job and upload it as an artifact. Pass the artifact name and the file path inside it.

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      # Build dist/app-linux.tar.gz here.
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: release-build
          path: dist/app-linux.tar.gz

  scan:
    needs: build
    uses: kobaltoxid/security-runtime/.github/workflows/scan.yml@RUNTIME_COMMIT_SHA
    with:
      release-artifact: release-build
      release-file: app-linux.tar.gz
```

The history job records the file's SHA-256 digest as the revision and uses the stream `release-<file name>`. SecDepth calls secpeel to identify the shipped components, and the saved run includes secpeel's `evidence.json`. A scheduled run that builds and scans the release is recorded with the trigger `scheduled`, so it scans again even when the digest has not changed. Set `stream` to keep the same history when the file name includes a version. The scan can use Git, `7z`, `zstd`, `nm`, `java`, and `unblob` when the runner provides them; secpeel records any missing tool as a coverage gap.

### Where history is kept

The history job stores each stream's runtime state in the GitHub Actions cache and uploads the run's summary, reports, and scan log as an artifact for 30 days. The job summary lists new, changed, and missing findings. Only one run per stream scans at a time, so runs do not overwrite each other's history. If several runs queue, GitHub keeps the newest and cancels the others.

The cache follows GitHub's access rules. A run can restore history saved on its own branch or the default branch, and GitHub removes cache entries that are not used for seven days. Run release scans from the default branch or a long-lived branch so each release sees the previous one. [Cache access rules](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
