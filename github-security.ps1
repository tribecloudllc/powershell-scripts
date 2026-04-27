<#
.SYNOPSIS
    Scans GitHub Actions workflow files for common security issues and generates an HTML report.

.DESCRIPTION
    Reads YAML workflow files from a repository's .github/workflows directory
    and checks for the following classes of security issue:
      - Missing 'permissions:' block (CRITICAL)
      - ${{ }} expressions inside run: blocks - script injection risk (CRITICAL)
      - Unsanitized expressions written to GITHUB_ENV (CRITICAL)
      - Use of pull_request_target trigger (CRITICAL)
      - Committed secrets matching common token patterns (CRITICAL)
      - Actions not pinned to a 40-char commit SHA (HIGH)

    Produces an HTML report summarising findings.

.PARAMETER RepoPath
    Path to the repository root that contains the .github/workflows directory.

.PARAMETER OutputFile
    Path where the HTML report will be written. Defaults to
    workflow-security-report.html in the current directory.

.EXAMPLE
    .\Test-GitHubActionsWorkflowSecurity.ps1 -RepoPath C:\repos\my-repo

.EXAMPLE
    .\Test-GitHubActionsWorkflowSecurity.ps1 -RepoPath . -OutputFile .\report.html

.NOTES
    Verbs used follow the PowerShell approved verbs list:
    https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepoPath,

    [Parameter()]
    [string]$OutputFile = "workflow-security-report.html"
)

function Get-WorkflowFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $workflowDir = Join-Path $Path ".github/workflows"
    $files  = @(Get-ChildItem -Path $workflowDir -Filter "*.yml"  -Recurse -ErrorAction SilentlyContinue)
    $files += @(Get-ChildItem -Path $workflowDir -Filter "*.yaml" -Recurse -ErrorAction SilentlyContinue)
    return $files
}

function Test-WorkflowPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Content,
        [Parameter(Mandatory = $true)] [string]$FileName
    )

    if ($Content -notmatch '(?m)^permissions:' -and $Content -notmatch '^\s{2,4}permissions:') {
        [PSCustomObject]@{
            Severity = "CRITICAL"
            File     = $FileName
            Line     = "-"
            Issue    = "No explicit 'permissions:' block found"
            Fix      = "Add 'permissions: read-all' at the top level, then grant only what each job needs."
        }
    }
}

function Find-WorkflowExpressionInRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string[]]$Lines,
        [Parameter(Mandatory = $true)] [string]$FileName
    )

    $inRunBlock = $false
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if ($line -match '^\s+run:') {
            $inRunBlock = $true
        }
        elseif ($inRunBlock -and $line -match '^\s+\w+:' -and $line -notmatch '^\s+\|') {
            $inRunBlock = $false
        }

        if ($inRunBlock -and $line -match '\$\{\{.*\}\}') {
            [PSCustomObject]@{
                Severity = "CRITICAL"
                File     = $FileName
                Line     = ($i + 1)
                Issue    = "Expression in run: block (script injection risk): " + $line.Trim()
                Fix      = "Pass the value via an env: variable instead: env: VAL=`${{ expr }}` then use `$VAL in the script."
            }
        }
    }
}

function Test-WorkflowEnvWrite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string[]]$Lines,
        [Parameter(Mandatory = $true)] [string]$FileName
    )

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '\$GITHUB_ENV' -and $Lines[$i] -match '\$\{\{') {
            [PSCustomObject]@{
                Severity = "CRITICAL"
                File     = $FileName
                Line     = ($i + 1)
                Issue    = "Unsanitized expression written to GITHUB_ENV: " + $Lines[$i].Trim()
                Fix      = "Sanitize or validate the value before writing to GITHUB_ENV, or use a trusted intermediate step."
            }
        }
    }
}

function Test-WorkflowTrigger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Content,
        [Parameter(Mandatory = $true)] [string[]]$Lines,
        [Parameter(Mandatory = $true)] [string]$FileName
    )

    if ($Content -match 'pull_request_target') {
        $lineNum = ($Lines | Select-String 'pull_request_target' | Select-Object -First 1).LineNumber
        [PSCustomObject]@{
            Severity = "CRITICAL"
            File     = $FileName
            Line     = $lineNum
            Issue    = "Unsafe trigger: pull_request_target detected"
            Fix      = "Avoid checking out or running code from the PR in pull_request_target context. If needed, use the 'workflow_run' trigger pattern instead."
        }
    }
}

function Find-CommittedSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string[]]$Lines,
        [Parameter(Mandatory = $true)] [string]$FileName
    )

    $secretPatterns = @(
        'ghp_[A-Za-z0-9]{36}',
        'AKIA[0-9A-Z]{16}',
        'AIza[0-9A-Za-z\-_]{35}',
        'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        'password\s*[:=]\s*\S+'
    )

    foreach ($pattern in $secretPatterns) {
        for ($i = 0; $i -lt $Lines.Count; $i++) {
            if ($Lines[$i] -match $pattern) {
                [PSCustomObject]@{
                    Severity = "CRITICAL"
                    File     = $FileName
                    Line     = ($i + 1)
                    Issue    = "Possible committed secret (pattern: $pattern): " + $Lines[$i].Trim()
                    Fix      = "Rotate/revoke the secret immediately. Use `${{ secrets.SECRET_NAME }} and remove the value from git history (git filter-repo)."
                }
            }
        }
    }
}

function Test-ActionPinning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string[]]$Lines,
        [Parameter(Mandatory = $true)] [string]$FileName
    )

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '^\s+uses:\s+(.+)') {
            $action = $matches[1].Trim()
            if ($action -notmatch '^\./' -and $action -notmatch '@[a-f0-9]{40}$') {
                [PSCustomObject]@{
                    Severity = "HIGH"
                    File     = $FileName
                    Line     = ($i + 1)
                    Issue    = "Action not pinned to commit SHA: $action"
                    Fix      = "Replace the tag/branch reference with the full commit SHA, e.g. uses: $($action.Split('@')[0])@<full-sha>  # tag comment"
                }
            }
        }
    }
}

function New-WorkflowSecurityReport {
    [CmdletBinding()]
    param(
        [Parameter()]                  [object[]]$Finding,
        [Parameter(Mandatory = $true)] [int]$ScannedCount,
        [Parameter(Mandatory = $true)] [string]$RepoName,
        [Parameter(Mandatory = $true)] [string]$OutputFile
    )

    $critical  = @($Finding | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $high      = @($Finding | Where-Object { $_.Severity -eq "HIGH" }).Count
    $total     = @($Finding).Count
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Build findings rows
    $rows = ""
    foreach ($f in (@($Finding) | Sort-Object Severity, File, Line)) {
        if ($null -eq $f) { continue }
        $badgeClass = if ($f.Severity -eq "CRITICAL") { "badge-critical" } else { "badge-high" }
        $rowClass   = if ($f.Severity -eq "CRITICAL") { "row-critical" }   else { "row-high" }
        $rows += @"
    <tr class="$rowClass">
        <td><span class="badge $badgeClass">$($f.Severity)</span></td>
        <td class="mono">$($f.File)</td>
        <td class="mono center">$($f.Line)</td>
        <td>$($f.Issue)</td>
        <td class="fix-cell">$($f.Fix)</td>
    </tr>
"@
    }
    if ($rows -eq "") {
        $rows = '<tr><td colspan="5" class="no-issues">No issues found - all checks passed.</td></tr>'
    }

    $statusColor = if ($critical -gt 0) { "#ef4444" } elseif ($high -gt 0) { "#f97316" }       else { "#22c55e" }
    $statusText  = if ($critical -gt 0) { "ACTION REQUIRED" } elseif ($high -gt 0) { "REVIEW NEEDED" } else { "PASSED" }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GitHub Actions Security Report - $RepoName</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:          #0d1117;
    --surface:     #161b22;
    --surface2:    #1c2128;
    --border:      #30363d;
    --text:        #e6edf3;
    --text-muted:  #7d8590;
    --critical:    #ef4444;
    --critical-bg: #2a1215;
    --high:        #f97316;
    --high-bg:     #2a1a0e;
    --accent:      #58a6ff;
    --green:       #22c55e;
    --mono:        'IBM Plex Mono', monospace;
    --sans:        'IBM Plex Sans', sans-serif;
  }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }
  .header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 28px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
  }
  .header-left h1 {
    font-size: 18px;
    font-weight: 600;
    letter-spacing: -0.3px;
    color: var(--text);
  }
  .header-left .repo {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--accent);
    margin-top: 4px;
  }
  .header-left .timestamp {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 2px;
  }
  .status-badge {
    padding: 8px 20px;
    border-radius: 6px;
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1px;
    background: $statusColor;
    color: #fff;
    opacity: 0.95;
  }
  .stats {
    display: flex;
    gap: 0;
    padding: 20px 40px;
    border-bottom: 1px solid var(--border);
    background: var(--surface2);
  }
  .stat {
    flex: 1;
    padding: 16px 24px;
    border-right: 1px solid var(--border);
  }
  .stat:last-child { border-right: none; }
  .stat-value {
    font-family: var(--mono);
    font-size: 28px;
    font-weight: 600;
    line-height: 1;
  }
  .stat-label {
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-top: 4px;
  }
  .stat-value.critical { color: var(--critical); }
  .stat-value.high     { color: var(--high); }
  .stat-value.neutral  { color: var(--accent); }
  .stat-value.green    { color: var(--green); }
  .main { padding: 28px 40px; }
  .section-title {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    margin-bottom: 14px;
  }
  .table-wrap {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  thead th {
    background: var(--surface2);
    padding: 10px 14px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: rgba(255,255,255,0.03); }
  td {
    padding: 10px 14px;
    vertical-align: top;
    font-size: 13px;
  }
  .row-critical { background: rgba(239,68,68,0.04); }
  .row-high     { background: rgba(249,115,22,0.04); }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.5px;
    white-space: nowrap;
  }
  .badge-critical { background: var(--critical-bg); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); }
  .badge-high     { background: var(--high-bg);     color: var(--high);     border: 1px solid rgba(249,115,22,0.3); }
  .mono   { font-family: var(--mono); font-size: 12px; }
  .center { text-align: center; }
  .fix-cell {
    color: var(--text-muted);
    font-size: 12px;
    min-width: 260px;
  }
  .no-issues {
    text-align: center;
    padding: 40px !important;
    color: var(--green);
    font-family: var(--mono);
  }
  .footer {
    padding: 20px 40px;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--text-muted);
    font-family: var(--mono);
  }
</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <h1>GitHub Actions Security Report</h1>
    <div class="repo">$RepoName</div>
    <div class="timestamp">Generated: $timestamp</div>
  </div>
  <div class="status-badge">$statusText</div>
</div>
<div class="stats">
  <div class="stat">
    <div class="stat-value neutral">$ScannedCount</div>
    <div class="stat-label">Workflows Scanned</div>
  </div>
  <div class="stat">
    <div class="stat-value $(if($total -eq 0){'green'}else{'neutral'})">$total</div>
    <div class="stat-label">Total Findings</div>
  </div>
  <div class="stat">
    <div class="stat-value $(if($critical -eq 0){'green'}else{'critical'})">$critical</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat">
    <div class="stat-value $(if($high -eq 0){'green'}else{'high'})">$high</div>
    <div class="stat-label">High</div>
  </div>
</div>
<div class="main">
  <div class="section-title">Findings</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>File</th>
          <th>Line</th>
          <th>Issue</th>
          <th>Recommended Fix</th>
        </tr>
      </thead>
      <tbody>
        $rows
      </tbody>
    </table>
  </div>
</div>
<div class="footer">
  Test-GitHubActionsWorkflowSecurity.ps1 -- checks: permissions | injection | GITHUB_ENV | pull_request_target | secrets | unpinned actions
</div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
}

function Test-GitHubActionsWorkflowSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter()]
        [string]$OutputFile = "workflow-security-report.html"
    )

    $workflows = Get-WorkflowFile -Path $RepoPath
    if (-not $workflows) {
        Write-Host "No workflow files found in $RepoPath/.github/workflows" -ForegroundColor Red
        return
    }

    $findings = foreach ($file in $workflows) {
        $content = Get-Content $file.FullName -Raw
        $lines   = Get-Content $file.FullName

        Test-WorkflowPermission       -Content $content -FileName $file.Name
        Find-WorkflowExpressionInRun  -Lines   $lines   -FileName $file.Name
        Test-WorkflowEnvWrite         -Lines   $lines   -FileName $file.Name
        Test-WorkflowTrigger          -Content $content -Lines $lines -FileName $file.Name
        Find-CommittedSecret          -Lines   $lines   -FileName $file.Name
        Test-ActionPinning            -Lines   $lines   -FileName $file.Name
    }

    New-WorkflowSecurityReport `
        -Finding      $findings `
        -ScannedCount $workflows.Count `
        -RepoName     (Split-Path $RepoPath -Leaf) `
        -OutputFile   $OutputFile

    Write-Host "Report saved to: $OutputFile" -ForegroundColor Green
    Start-Process $OutputFile
}

# Entry point - execute when invoked as a script
Test-GitHubActionsWorkflowSecurity -RepoPath $RepoPath -OutputFile $OutputFile
