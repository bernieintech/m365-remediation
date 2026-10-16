# M365 Security Remediation

An **approval-gated, least-privilege, fully-audited** remediation tool for Microsoft 365 / Microsoft Entra ID, written in PowerShell on the Microsoft Graph SDK.

It is the **"fix" counterpart** to a read-only security assessment: where an assessor only *reports* problems, this tool *closes* them — but it never makes a change without showing exactly what it will do and waiting for an explicit human **`YES`**, and it writes a timestamped record of every action.

> Built as the companion to [m365-security-assessment](https://github.com/bernieintech/m365-security-assessment). Assessment finds the gaps; remediation fixes them, safely.

## What it fixes

| `-Fix` | Finding it closes | What it does |
|---|---|---|
| `GlobalAdmin` | Privileged-role sprawl | Removes the **Global Administrator** role from accounts not on an approved allow-list (the account itself is kept) |
| `LicenseWaste` | Paying for nothing | Removes paid licenses from **disabled** accounts to reclaim the seats (cost savings) |
| `All` | — | Runs every fix (default) |

## How it works — the remediation loop

Every fix runs the same disciplined loop a careful administrator would:

1. **Detect** — find the problem.
2. **Propose** — show, in plain English, exactly what it would change and why.
3. **Preview** — run the change with `-WhatIf` (shows the effect, changes nothing).
4. **Ask** — pause for the operator to type `YES` (per item; anything else skips).
5. **Fix** — make the change — *only* on `YES`.
6. **Verify** — re-check, with a short wait-and-retry so the result reflects Entra's eventual consistency.
7. **Log** — append a timestamped record to `remediation-log/`.

## Safety by design

- **Nothing changes without an explicit typed `YES`.** `-PreviewOnly` makes the whole run look-only.
- **Least privilege, per run.** Requests only the write scope(s) the chosen fix needs — not a blanket admin token.
- **Anti-lockout (GlobalAdmin):** never removes an approved admin, never removes the account you signed in with, and aborts if no approved admin would remain.
- **Scoped blast radius (LicenseWaste):** only ever targets **disabled** accounts; enabled users are never touched.
- **Separate from assessment.** The read-only assessor refuses to run with any write scope; this tool is a distinct script with its own narrowly-scoped write permission. Looking and changing never blur.

## The audit trail

Every run and every action is written to `remediation-log/Remediation-<timestamp>.log`:

```
2026-01-01 09:00:00  [OK]      Connected as admin@contoso.onmicrosoft.com  [remediation mode: GlobalAdmin]
2026-01-01 09:00:03  [INFO]    Current Global Administrators (3): admin@, breakglass@, finance-user@
2026-01-01 09:00:12  [ACTION]  REMOVING Global Administrator from finance-user@ ...
2026-01-01 09:00:13  [OK]      REMOVED Global Administrator from finance-user@ by admin@
2026-01-01 09:00:17  [OK]      Verification - Global Administrators now (2): admin@, breakglass@
```

This answers the four questions an auditor or cyber-insurer asks — **who, what, when, and the result** — supporting **accountability** and **non-repudiation**. (Logs are git-ignored; they contain tenant specifics.)

## Usage

```
# Preview everything, change nothing (safe to run anytime):
pwsh ./Invoke-M365Remediation.ps1 -PreviewOnly

# Fix one area, with approval prompts:
pwsh ./Invoke-M365Remediation.ps1 -Fix GlobalAdmin
pwsh ./Invoke-M365Remediation.ps1 -Fix LicenseWaste

# Run all fixes (default):
pwsh ./Invoke-M365Remediation.ps1
```

On first use it signs in with the **device-code flow** and requests only the scopes the selected fix needs. Edit the `$ApprovedGlobalAdmins` list at the top of the script to match your tenant's legitimate admins.

### Scopes requested (per fix, least privilege)

| Fix | Read | Write |
|---|---|---|
| GlobalAdmin | `Directory.Read.All` | `RoleManagement.ReadWrite.Directory` |
| LicenseWaste | `Directory.Read.All` | `LicenseAssignment.ReadWrite.All` |

## Setup

- PowerShell 7+ (`pwsh`)
- Microsoft Graph PowerShell SDK, including **`Microsoft.Graph.Users.Actions`** (for the license fix):

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, `
               Microsoft.Graph.Users, Microsoft.Graph.Users.Actions `
               -RequiredVersion 2.41.1 -Scope CurrentUser -Repository PSGallery
```

- An account with the necessary admin role to apply the change (e.g. Privileged Role Administrator for role removal, License Administrator for license changes).

## Design principles

- **Advisory-first.** Human approval gates every change; this is the safe foundation the approval model is built on before any future unattended automation.
- **Scanner-agnostic by intent.** The findings it fixes can come from this project's assessor or any other (including CISA ScubaGear); the value is the safe, logged *fix*, not the scan.
- **Idempotent & re-runnable.** Running again when there's nothing to fix simply reports "nothing to do."
- **Eventually-consistent aware.** Verification waits briefly and retries, so a change that's still propagating isn't misreported.

## Limitations / roadmap

- **More fixes:** app-consent tightening, external-sharing hardening, ghost-account disable, redundant-policy cleanup.
- **Plain-English preview:** translate the raw Graph `-WhatIf` line into owner-friendly language.
- **Rollback records:** capture enough to reverse a change, not just log it.
- **Approval-gated agent:** wrap these fixes behind an audit-ready agent with per-tenant scoped identity and a full action log (the Phase-3 goal).

## Skills applied

Microsoft Entra ID / Microsoft 365 administration · Microsoft Graph PowerShell SDK (write operations) · identity & access management · least privilege · change management (propose → approve → execute → verify → log) · defensive scripting (allow-lists, lockout guards, `-WhatIf`, idempotency, eventual-consistency handling) · audit logging / accountability · Git/GitHub PR workflow with protected branches.

Maps to **CompTIA Security+** (IAM, least privilege, accountability/non-repudiation, change management) and **Microsoft AZ-800** (Entra identity and Graph administration).

## License

All rights reserved (portfolio demonstration).
