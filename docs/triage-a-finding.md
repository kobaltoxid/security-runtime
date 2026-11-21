# Triage a SecDepth finding

When SecDepth flags a finding for review, you can ask Claude whether the evidence in the scan supports the reported conclusion. The worker reviews one finding at a time and saves each step in SQLite. If the review stops before it reaches a verdict, you can resume with the same scan files, model, and database.

## Get the scan artifact

For a local review, use Python 3 and an authenticated `claude2` command. If `claude2` is a shell function, define it in the configuration that zsh reads when it opens an interactive shell. Use scan evidence that you are authorized to send through that account.

To use the public Go pilot, open a recent successful scan in GitHub Actions. Set `SCAN_RUN_ID` to the number at the end of the run URL and `SCAN_ARTIFACT_NAME` to the name shown under **Artifacts**.

```sh
gh run download "$SCAN_RUN_ID" \
  --repo kobaltoxid/bg-cars-discord-bot \
  --name "$SCAN_ARTIFACT_NAME" \
  --dir .state/go-pilot
```

## Review and resume

From the security-runtime checkout, run the first step. The worker selects the first finding flagged for review unless you pass `--finding` with an advisory ID. The default model is Claude Haiku.

```sh
python3 triage.py .state/go-pilot --db .state/triage.sqlite3 --step
```

Run the same command without `--step` to continue to a final verdict. You can also press Ctrl-C during a normal run and repeat the command to resume. The worker repeats any model call whose result was interrupted before the checkpoint committed.

```sh
python3 triage.py .state/go-pilot --db .state/triage.sqlite3
```

## Read the result

Read the verdict alongside the original scan. The JSON names the records Claude cited. The worker returns `insufficient_evidence` if Claude abstains or if the runtime rejects the proposed action. If you repeat a completed review with the same scan files, model, provider, policy version, and database, the worker returns the saved verdict.

The runtime validates each proposed action before acting on it. Claude can request the recorded checks or the affected components for the selected finding. The worker allows up to two evidence requests and saves the records it supplies. Each decision comes from a separate model call with tools disabled.

## Runner authentication

The local worker uses `claude2`. The hosted pilot uses Claude Code with a subscription OAuth token stored as an Actions secret in the `triage` environment. GitHub restricts that environment to `main`. [Claude Code CI authentication](https://code.claude.com/docs/en/github-actions)

Run these commands in your own interactive terminal. Sign in to your personal subscription and paste the token at the GitHub CLI prompt.

```sh
claude2 setup-token
gh secret set CLAUDE_CODE_OAUTH_TOKEN \
  --repo kobaltoxid/security-runtime \
  --env triage
```

## Run hosted triage

Dispatch the hosted pilot from `main`. The first job scans a pinned commit of the public Go pilot and saves its report and checks. The second job uses those files to review one finding and saves the verdict and SQLite checkpoint as artifacts. Only the model step receives the subscription token.

```sh
gh workflow run triage.yml --repo kobaltoxid/security-runtime --ref main
```

Use `-f verify_only=true` to test the scan, artifact handoff, and CLI installation without making a model request.

Open the run under **Actions** to see the check and download its artifacts. The hosted workflow starts a fresh database per run and resumes from that database between its checkpoint and verdict steps.

## Review a pull request scan

Add the `secdepth-triage` label to an open pull request in the Go Discord bot repository. The runtime checks labeled pull requests every 15 minutes. It waits for a successful SecDepth scan of the current commit, then verifies the scan workflow and artifact before asking Claude to review one flagged finding.

To check for a labeled pull request immediately, open **PR label triage** in GitHub Actions and choose **Run workflow** on `main`. The workflow takes no inputs. [PR label triage](https://github.com/kobaltoxid/security-runtime/actions/workflows/pr-triage.yml)

Each run handles one eligible pull request. The runtime keeps a record of the reviewed commit so a later run can skip it. If the report has no flagged findings, the runtime records that outcome without calling Claude. Leave the label in place to review future commits or remove it to stop requesting further reviews.

Find the verdict in the artifacts of the **PR label triage** run. The artifact name contains the pull request number and commit, and `source.json` records the original scan and pull request. The pilot accepts pull requests whose source branch is in the Go Discord bot repository and whose target branch is `main`.
