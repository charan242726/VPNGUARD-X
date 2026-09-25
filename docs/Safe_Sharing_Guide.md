# Sharing VPNGUARD-X code and experiment evidence

Run these commands on the Linux lab machine, from the **VPNGUARD-X** project
directory. Retain the unmodified 1.2 GB capture tree locally. Never initialize
or push a Git repository containing `artifacts/` or `data/generated/`.

## Send experimental evidence for private review

```bash
python scripts/prepare_safe_review.py --project . \
  --output ../VPNGUARD-X_safe_review.zip
```

The script reads every available `ground_truth.json`, checks each referenced
PCAP SHA-256, inventories seed/stack/outcome/variant coverage, and checks plan
coverage. It packages allowlisted JSON/CSV metrics, ground truth, loss metadata
and manifests. It includes split manifests and metric summaries under both
`artifacts/results` and `artifacts/results_corrected` when present. Its inventory
also reports ground-truth/scenario-manifest hash mismatches, result counts,
packet-loss metric keys, and null dedicated-OOD metrics. It excludes PCAPs,
endpoint configuration files, raw SA
telemetry, key material, logs and model weights. Read `REVIEW_INVENTORY.json`
inside the ZIP before sharing. A nonzero exit code indicates an integrity,
credential, or size issue; resolve the reported file paths before using the
bundle. If a required result is absent, the bundle does not generate it.

Upload **only this ZIP** here for experimental assessment; a GitHub link is
unnecessary for the 1.2 GB range. This ZIP is for private review and includes
experiment metadata such as local paths and IP addresses; manually review it
before any *public* release.

## GitHub source repository

Keep the repository source only. `.gitignore` excludes generated PCAPs,
`artifacts/`, `data/generated/`, model weights, endpoint secrets, and QA images.
It also keeps the unpublished manuscript drafts local.
Do not use GitHub's browser upload for the entire project directory. Start with
a **new private** repository after the students inspect the files to be staged.
From the project directory, before the first commit:

```bash
git init
git add .
git status --short
python scripts/prepare_safe_review.py --project . \
  --output ../VPNGUARD-X_safe_review.zip
```

If the command reports a tracked generated file, secret, or oversized file,
stop and remove it from the index with `git rm --cached -- <path>` (the local
file remains). Check `git status --short` again. A successful current-index
check does **not** examine old commits. If this is an existing Git repository,
inspect **all branches and commit history** for previously committed secrets
and captures before pushing; deleting a file in a new commit does not remove
it from history. Rotate any credential that has escaped the isolated lab.

For code review, supply a link to a repository that is accessible to the
reviewer. A private repository without granted access cannot be inspected from
a link alone. Alternatively upload the reproducibility source archive built by
`python scripts/build_release.py --output ../VPNGUARD-X_source.zip --version 0.2.1`.
Do not place the 1.2 GB capture archive or secret-containing run directories
in Git or Git LFS for this review.
