<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: MIT
-->

# OpenTofu dependency maintenance

The Deployment reconciliation workflow authenticates the original Dependabot
proposals and regenerates official signed provider locks. The Google roots
require matching signed proposals and share one repair. DigitalOcean has its
own repair. The original bot commits remain the record of dependency intent.

A dedicated App uses GitHub's `createCommitOnBranch` mutation on one derived
`automation/opentofu/<provider>/<snapshot>` ref. The snapshot binds the protected
base, provider version and original proposal heads. GitHub supplies the commit
identity and signature. The writer reads back the verified signature, parent
and exact files before opening the PR. A new base or proposal head produces a
new snapshot. An overlapping independently owned PR defers the automated
repair. Dependabot's native lifecycle handles original proposals whose updates
are already on main.

A separate trusted workflow job reproduces the signed intent and official
provider hashes from protected-base code. It compares the exact repaired blobs
and checks the normal protected status on the same head and base. Only then
does it request GitHub's automatic squash merge with an exact-head guard. With
all required checks green GitHub can merge immediately. The scheduled pass
retries pending checks, canceled runs and updated proposal snapshots. The
runtime and Quadlet checks remain required.

## App authorization

1. After the reconciler source is accepted on protected main, register a
   private GitHub App owned by SecPal with slug
   `secpal-opentofu-reconciler`. Disable webhooks and leave user authorization
   disabled. Configure repository **Contents** and **Pull requests** as
   **Read and write** and retain the automatic **Metadata** read permission.
   Leave all other permissions unset, including Workflows and Administration.
2. Install the App with **Only select repositories**, selecting only
   `SecPal/deployment`. Keep the App outside branch-protection bypass lists.
   Contents write is repository-wide API authority. The trusted workflow
   restricts its own writes to derived reconciliation branches and exact
   provider files. Independent verification and existing protections apply to
   main.
3. Generate the App private key through the App settings and store it using
   approved secret custody. From a trusted terminal, record the repository
   Actions secret and enable the workflow with the numeric App ID.

   ```sh
   gh secret set OPENTOFU_RECONCILER_PRIVATE_KEY -R SecPal/deployment < "$APP_KEY_FILE"
   gh variable set OPENTOFU_RECONCILER_APP_ID -R SecPal/deployment --body "$APP_ID"
   ```

   The workflow requests installation tokens scoped to Deployment with only the
   two write permissions. The App key and token are inputs to trusted steps
   after read-only reconciliation. Provider tooling receives a separate
   environment. Repair PR verification uses the workflow token and receives
   neither App credential.

4. Verify the installation scope in the organization App settings. On the next
   scheduled pass or signed proposal event, verify the App-authored repair and
   ordinary hosted checks. Substitute the observed PR number and exact head.

   ```sh
   gh api orgs/SecPal/installations --paginate \
     --jq '.installations[] | select(.app_slug=="secpal-opentofu-reconciler") | {repository_selection,permissions}'
   gh api "repos/SecPal/deployment/commits/$REPAIR_HEAD" \
     --jq '{sha,author:.author.login,verified:.commit.verification.verified,parents:[.parents[].sha]}'
   gh pr checks "$REPAIR_PR" -R SecPal/deployment --required
   gh pr view "$REPAIR_PR" -R SecPal/deployment --json headRefOid,autoMergeRequest,state,mergeCommit
   ```

   A failing runtime check leaves the repair open. The workflow records source
   admission and requests protected merge only after GitHub reports readiness.

[GitHub App installation authentication][app] and GitHub's
[bot commit-signing rules][signing] describe the required identity. GitHub
[documents why installation-token PR events run required workflows][events].

[app]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation
[signing]: https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#signature-verification-for-bots
[events]: https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow#triggering-a-workflow-from-a-workflow
