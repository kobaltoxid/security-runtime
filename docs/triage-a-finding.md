# Triage a SecDepth finding

Run an evidence review for one flagged finding from a SecDepth report directory or a downloaded GitHub Actions artifact. The worker checkpoints the review in a local SQLite database. Reuse the same artifact, model, and database to resume it.

## Get the scan artifact

Use Python 3 and an authenticated `claude2` command. On machines where `claude2` is a shell function, define it in your interactive zsh configuration. The example uses a public scan artifact from the Go pilot. Review only data you are authorized to send through that account.

```sh
gh run download 44832734825 \
  --repo kobaltoxid/bg-cars-discord-bot \
  --name secdepth-pr-1-44832734825-1 \
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

The worker returns a JSON verdict with evidence references or an `insufficient_evidence` result. A repeated invocation with the same input and model returns the stored verdict. Keep the original scan artifacts for the evidence behind the review.

The runtime selects which records each evidence request may see and validates the model's proposed action before applying it. Each decision comes from a separate model call with tools disabled, and the worker allows at most two evidence requests before a verdict. The worker stores its own state and uses the SecDepth evidence supplied with the run.

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
