# Post an approved comment

Use the write gate when the runtime should comment on a pull request only after a person approves the exact text. The gate records the request in SQLite, ties the approval to a digest of the comment, and posts it at most once. You need Python 3 and a `gh` CLI signed in to an account that can comment on the repository.

## Propose the comment

Write the comment body to a file, then record the request from the security-runtime checkout.

```sh
python3 main.py comment --db .state/write-gate.sqlite3 propose \
  --repo OWNER/REPO --pr 12 --body-file comment.md
```

The runtime reads the pull request's current head commit and prints the request with its `digest` and `status: pending`. The digest covers the repository, pull request number, head commit, and body. A different body or destination produces a different digest that needs its own approval.

## Approve it

Read the printed body, then approve that digest. The runtime records the GitHub login of the signed-in `gh` account as the approver.

```sh
python3 main.py comment --db .state/write-gate.sqlite3 approve DIGEST
```

Run `show DIGEST` to print the request again before approving.

## Post it

```sh
python3 main.py comment --db .state/write-gate.sqlite3 post DIGEST
```

The runtime refuses to post when the request is not approved, the stored payload no longer matches its digest, or the pull request is closed or has a new head commit. In those cases, propose the comment again.

Each posted comment ends with a hidden `security-runtime-write` marker that contains the digest. Before posting, the runtime looks for a comment by the same account with that marker. Repeating `post` after a success, or after a failure that happened once GitHub had accepted the comment, records the existing comment instead of posting a second one.
