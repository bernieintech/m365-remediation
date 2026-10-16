<#
.SYNOPSIS
    Approval-gated Microsoft 365 / Entra remediation tool (multi-fix).

.DESCRIPTION
    The safe counterpart to the read-only assessment tool. Where the assessor only
    LOOKS, this tool can CHANGE the tenant - but only specific, reversible actions,
    and only after a human types an explicit confirmation.

    Each fix runs the same loop a careful human would:
        1. Detect   - find the problem.
        2. Propose  - show, in plain English, exactly what it would change and why.
        3. Preview  - run the change with -WhatIf (shows the effect, changes nothing).
        4. Ask      - wait for the operator to type YES (per item).
        5. Fix      - make the change (only on YES).
        6. Verify   - re-check and report.
        7. Log      - append a timestamped record to remediation-log/.

    FIXES AVAILABLE (-Fix):
        GlobalAdmin   - remove Global Administrator from accounts not on the approved list.
        LicenseWaste  - remove paid licenses from DISABLED accounts (reclaim cost).
        All           - run every fix (default).

    SAFETY BY DESIGN:
      - Least privilege, per run: only requests the write scope(s) the chosen fix needs.
      - GlobalAdmin: never touches an approved admin, never removes you, never risks lockout.
      - LicenseWaste: only ever targets DISABLED accounts (enabled users are never touched).
      - Nothing changes without an explicit typed "YES" (unless -PreviewOnly, which never
        changes anything at all).

.PARAMETER Fix
    Which remediation to run: GlobalAdmin, LicenseWaste, or All (default).

.PARAMETER PreviewOnly
    Show the proposal + -WhatIf preview only. Never prompts, never changes anything.

.NOTES
    Author : Magic Ben Ventures
    Output : <script folder>/remediation-log/Remediation-<timestamp>.log
    Needs  : Microsoft Graph PowerShell modules, incl. Microsoft.Graph.Users.Actions (for the license fix).
#>

param(
    [ValidateSet('GlobalAdmin', 'LicenseWaste', 'All')]
    [string]$Fix = 'All',
    [switch]$PreviewOnly
)

# ---------------------------------------------------------------------------
# CONFIG - accounts allowed to KEEP Global Administrator (primary + break-glass).
# ---------------------------------------------------------------------------
$ApprovedGlobalAdmins = @(
    'adminbernie10@magicbventureslab.onmicrosoft.com',
    'sglass@magicbventureslab.onmicrosoft.com'
)

# ---------------------------------------------------------------------------
# Logging - every run and every action is written to a timestamped file.
# ---------------------------------------------------------------------------
$script:LogPath = Join-Path $PSScriptRoot ("remediation-log/Remediation-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0}  [{1}]  {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $dir  = Split-Path -Parent $script:LogPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Add-Content -Path $script:LogPath -Value $line
    $color = switch ($Level) { 'ACTION' {'Yellow'} 'OK' {'Green'} 'WARN' {'DarkYellow'} 'ERROR' {'Red'} default {'Gray'} }
    Write-Host $line -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# Re-read a count with a short wait+retry. Entra is "eventually consistent":
# a read right after a write can still show the OLD value until the directory's
# copies sync (usually a few seconds). This makes the verify step trustworthy.
# ---------------------------------------------------------------------------
function Invoke-WithRetry {
    param([scriptblock]$Check, [int]$Expected, [int]$MaxTries = 5, [int]$DelaySeconds = 4)
    $result = & $Check
    for ($i = 1; $i -le $MaxTries -and $result -gt $Expected; $i++) {
        Write-Log ("Change not fully synced yet (saw {0}, expecting {1}); waiting {2}s for Entra to catch up... [try {3}/{4}]" -f $result, $Expected, $DelaySeconds, $i, $MaxTries) 'INFO'
        Start-Sleep -Seconds $DelaySeconds
        $result = & $Check
    }
    return $result
}

# ---------------------------------------------------------------------------
# Connect with only the scopes this run needs. Reuse an existing sign-in when
# it already has the required write scope(s) (so signing in by hand first works).
# ---------------------------------------------------------------------------
function Connect-Remediation {
    param([string[]]$RequiredScopes)
    $writeScopes = @($RequiredScopes | Where-Object { $_ -like '*ReadWrite*' })
    $ctx = Get-MgContext
    $haveAll = $ctx -and $ctx.Account -and -not (@($writeScopes | Where-Object { $ctx.Scopes -notcontains $_ }))
    if (-not $haveAll) {
        Connect-MgGraph -UseDeviceCode -Scopes $RequiredScopes -NoWelcome
        $ctx = Get-MgContext
    }
    if (-not $ctx -or -not $ctx.Account) {
        throw "Authentication failed - no active Microsoft Graph session. Aborting."
    }
    $missing = @($writeScopes | Where-Object { $ctx.Scopes -notcontains $_ })
    if ($missing) {
        throw "REFUSING TO RUN: missing required write scope(s): $($missing -join ', '). Cannot remediate safely."
    }
    Write-Log ("Connected as {0}  [remediation mode: {1}]" -f $ctx.Account, $Fix) 'OK'
    return $ctx.Account
}

# ===========================================================================
# FIX: Global Administrator sprawl
# ===========================================================================
function Get-GlobalAdmin {
    $role = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
    if (-not $role) { throw "Could not find the Global Administrator role in this tenant." }
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
    $admins = foreach ($m in $members) {
        [PSCustomObject]@{ Upn = $m.AdditionalProperties.userPrincipalName; Id = $m.Id; RoleId = $role.Id }
    }
    return @($admins | Where-Object { $_.Upn })
}

function Repair-GlobalAdminSprawl {
    param([string]$Operator)
    Write-Log "=== FIX: Global Administrator sprawl ===" 'INFO'

    $admins = Get-GlobalAdmin
    Write-Log ("Current Global Administrators ({0}): {1}" -f $admins.Count, ($admins.Upn -join ', '))

    $candidates      = @($admins | Where-Object { $ApprovedGlobalAdmins -notcontains $_.Upn })
    $approvedPresent = @($admins | Where-Object { $ApprovedGlobalAdmins -contains $_.Upn })

    if ($approvedPresent.Count -eq 0) {
        Write-Log "ABORT: none of the approved admins currently hold Global Administrator. Refusing to remove anyone (lockout risk)." 'ERROR'
        return
    }
    if ($candidates.Count -eq 0) {
        Write-Log "No admin sprawl found - every Global Administrator is on the approved list. Nothing to do." 'OK'
        return
    }

    Write-Host ""
    Write-Host "PROPOSED REMEDIATION - Global Admin sprawl" -ForegroundColor Cyan
    Write-Host "These account(s) hold Global Administrator but are NOT on the approved list:"
    foreach ($c in $candidates) { Write-Host ("   - {0}" -f $c.Upn) -ForegroundColor Yellow }
    Write-Host "Proposed action: remove the Global Administrator role from each (the account itself is kept)."
    Write-Host ""

    $removed = 0
    foreach ($c in $candidates) {
        if ($c.Upn -eq $Operator) {
            Write-Log ("SKIP {0}: this is the account you are signed in with - refusing to remove yourself (lockout guard)." -f $c.Upn) 'WARN'
            continue
        }
        Write-Host ("--- {0} ---" -f $c.Upn) -ForegroundColor Cyan
        Write-Host "Preview (no change is made):"
        Remove-MgDirectoryRoleMemberDirectoryObjectByRef -DirectoryRoleId $c.RoleId -DirectoryObjectId $c.Id -WhatIf

        if ($PreviewOnly) { Write-Log ("PREVIEW ONLY for {0}: would remove Global Administrator. No change made." -f $c.Upn) 'INFO'; continue }

        $answer = Read-Host ("Remove Global Administrator from {0}? Type YES to confirm (anything else skips)" -f $c.Upn)
        if ($answer -ne 'YES') { Write-Log ("SKIPPED {0} by operator (answer: '{1}')." -f $c.Upn, $answer) 'WARN'; continue }

        try {
            Write-Log ("REMOVING Global Administrator from {0} ..." -f $c.Upn) 'ACTION'
            Remove-MgDirectoryRoleMemberDirectoryObjectByRef -DirectoryRoleId $c.RoleId -DirectoryObjectId $c.Id -PassThru | Out-Null
            $removed++
            Write-Log ("REMOVED Global Administrator from {0} by {1}." -f $c.Upn, $Operator) 'OK'
        }
        catch { Write-Log ("FAILED to remove {0}: {1}" -f $c.Upn, $_.Exception.Message) 'ERROR' }
    }

    $expected = $admins.Count - $removed
    $null = Invoke-WithRetry -Check { (Get-GlobalAdmin).Count } -Expected $expected
    $after = Get-GlobalAdmin
    Write-Log ("Verification - Global Administrators now ({0}): {1}" -f $after.Count, ($after.Upn -join ', ')) 'OK'
}

# ===========================================================================
# FIX: License waste (DISABLED accounts that still hold paid licenses)
# ===========================================================================
function Get-LicenseWaste {
    $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses
    $waste = foreach ($u in ($users | Where-Object { -not $_.AccountEnabled -and $_.AssignedLicenses.Count -gt 0 })) {
        [PSCustomObject]@{ Upn = $u.UserPrincipalName; Id = $u.Id; SkuIds = @($u.AssignedLicenses.SkuId) }
    }
    return @($waste)
}

function Repair-LicenseWaste {
    param([string]$Operator)
    Write-Log "=== FIX: License waste (disabled-but-licensed accounts) ===" 'INFO'

    # Friendly names for licenses (SkuId -> SkuPartNumber), so the proposal is readable.
    $skuMap = @{}
    foreach ($s in Get-MgSubscribedSku -All) { $skuMap[$s.SkuId] = $s.SkuPartNumber }
    $nameOf = { param($ids) ($ids | ForEach-Object { if ($skuMap[$_]) { $skuMap[$_] } else { $_ } }) -join ', ' }

    $waste = Get-LicenseWaste
    if ($waste.Count -eq 0) {
        Write-Log "No license waste found - no disabled accounts hold licenses. Nothing to do." 'OK'
        return
    }

    Write-Host ""
    Write-Host "PROPOSED REMEDIATION - License waste" -ForegroundColor Cyan
    Write-Host "These account(s) are DISABLED but still hold paid license(s):"
    foreach ($w in $waste) { Write-Host ("   - {0}  [{1}]" -f $w.Upn, (& $nameOf $w.SkuIds)) -ForegroundColor Yellow }
    Write-Host "Proposed action: remove the license(s) to reclaim the paid seat(s). The account stays (disabled)."
    Write-Host "NOTE: removing a license can start a retention countdown on that user's mailbox/OneDrive data."
    Write-Host "      For a real client, convert the mailbox to Shared (or confirm retention) BEFORE removing." -ForegroundColor DarkYellow
    Write-Host ""

    $removed = 0
    foreach ($w in $waste) {
        $names = & $nameOf $w.SkuIds
        Write-Host ("--- {0}  [{1}] ---" -f $w.Upn, $names) -ForegroundColor Cyan
        Write-Host "Preview (no change is made):"
        Set-MgUserLicense -UserId $w.Id -AddLicenses @() -RemoveLicenses $w.SkuIds -WhatIf

        if ($PreviewOnly) { Write-Log ("PREVIEW ONLY for {0}: would remove license(s) [{1}]. No change made." -f $w.Upn, $names) 'INFO'; continue }

        $answer = Read-Host ("Remove license(s) [{0}] from {1}? Type YES to confirm (anything else skips)" -f $names, $w.Upn)
        if ($answer -ne 'YES') { Write-Log ("SKIPPED {0} by operator (answer: '{1}')." -f $w.Upn, $answer) 'WARN'; continue }

        try {
            Write-Log ("REMOVING license(s) [{0}] from {1} ..." -f $names, $w.Upn) 'ACTION'
            Set-MgUserLicense -UserId $w.Id -AddLicenses @() -RemoveLicenses $w.SkuIds | Out-Null
            $removed++
            Write-Log ("REMOVED license(s) [{0}] from {1} by {2}." -f $names, $w.Upn, $Operator) 'OK'
        }
        catch { Write-Log ("FAILED to remove license(s) from {0}: {1}" -f $w.Upn, $_.Exception.Message) 'ERROR' }
    }

    $expected = $waste.Count - $removed
    $afterCount = Invoke-WithRetry -Check { (Get-LicenseWaste).Count } -Expected $expected
    Write-Log ("Verification - disabled-but-licensed accounts now: {0}" -f $afterCount) 'OK'
}

# ===========================================================================
# MAIN
# ===========================================================================
Write-Host "M365 / Entra Remediation - approval-gated, least-privilege, fully logged." -ForegroundColor Cyan
Write-Host ("Fix selected: {0}" -f $Fix) -ForegroundColor Cyan
if ($PreviewOnly) { Write-Host "MODE: PREVIEW ONLY - nothing will be changed." -ForegroundColor Green }
Write-Host ""

# Build the minimal scope set for the chosen fix(es).
$scopes = @('Directory.Read.All')
if ($Fix -in @('GlobalAdmin','All'))  { $scopes += 'RoleManagement.ReadWrite.Directory' }
if ($Fix -in @('LicenseWaste','All')) { $scopes += 'LicenseAssignment.ReadWrite.All' }

$operator = Connect-Remediation -RequiredScopes $scopes

if ($Fix -in @('GlobalAdmin','All'))  { Repair-GlobalAdminSprawl -Operator $operator }
if ($Fix -in @('LicenseWaste','All')) { Repair-LicenseWaste      -Operator $operator }

Write-Host ""
Write-Log ("Done. Full log saved to: {0}" -f $script:LogPath) 'OK'
