# Security runtime

A pull request changes the code we are about to ship. GitHub Actions runs SecDepth on that exact commit and saves a report of known advisories and gaps in scan coverage. When SecDepth flags a finding for review, a maintainer can ask Claude to read the evidence. The verdict sits beside the original scan report, so readers can see what SecDepth found and what Claude concluded.

The hosted pull request review is available for the [Go Discord bot pilot](https://github.com/kobaltoxid/bg-cars-discord-bot/pull/1).

You can also scan a source checkout or release artifact locally. When SecDepth receives a compiled artifact, it uses secpeel to identify the components inside it and collect evidence about the code that shipped.

Run `python3 main.py --help` to see the commands for scanning, watching a target, and reviewing a finding.

- [Use the reusable GitHub Actions workflow](docs/monitor-a-target.md#run-on-github-actions)
- [Run a local scan](docs/monitor-a-target.md#run-a-scan)
- [Review a flagged finding and resume an interrupted review](docs/triage-a-finding.md)
- [Review loop design](docs/review-loop-design.md)
