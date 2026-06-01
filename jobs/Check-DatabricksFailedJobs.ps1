#Requires -Version 5.1
<#
.SYNOPSIS
    Daily Databricks job-health check. Lists job runs in a look-back window,
    classifies them (success / failed / cancelled / running), and optionally
    posts a formatted summary to a Microsoft Teams channel via Incoming Webhook
    and/or writes a self-contained HTML report.

.DESCRIPTION
    Uses the Databricks CLI (v0.205+, the Go-based CLI) `jobs list-runs` command
    with `--output json`. Pagination is handled via the `next_page_token`
    field returned in the JSON body (the documented mechanism for the new CLI),
    with a bare-array fallback for builds that stream results without an envelope.

    Authentication is delegated entirely to the CLI:
      - -Profile <name>  (a profile in ~/.databrickscfg), OR
      - env vars DATABRICKS_HOST + DATABRICKS_TOKEN, OR
      - the default profile.

    Designed to be run headless from Task Scheduler / cron every morning.

.PARAMETER Profile
    Optional Databricks CLI config profile name.

.PARAMETER LookbackHours
    Hours back to inspect for runs that started in the window. Default: 24.

.PARAMETER TeamsWebhookUrl
    Optional. Microsoft Teams Incoming Webhook URL. If supplied, an Adaptive
    Card summary is posted to that channel. Can also be set via the
    DATABRICKS_TEAMS_WEBHOOK environment variable.

.PARAMETER HtmlReportPath
    Optional. Path to write a self-contained HTML dashboard.

.PARAMETER TreatCancelledAsFailure
    If set, CANCELED runs are counted as failures. Default: reported separately.

.PARAMETER AlwaysPostToTeams
    By default the Teams card posts only when there is >=1 failure. Set this to
    post a green "all healthy" card too.

.PARAMETER WorkspaceUrl
    Optional. Base workspace URL used in the report header / link fallback.

.EXAMPLE
    .\Check-DatabricksFailedJobs.ps1 -Profile prod -TeamsWebhookUrl $env:HOOK -AlwaysPostToTeams

.EXAMPLE
    .\Check-DatabricksFailedJobs.ps1 -Profile prod -HtmlReportPath .\databricks-health.html

.NOTES
    Exit codes: 0 = no failures, 1 = one or more failures, 2 = script/CLI error.
#>

[CmdletBinding()]
param(
    [string]$Profile,
    [int]$LookbackHours = 24,
    [string]$TeamsWebhookUrl = $env:DATABRICKS_TEAMS_WEBHOOK,
    [string]$HtmlReportPath,
    [switch]$TreatCancelledAsFailure,
    [switch]$AlwaysPostToTeams,
    [string]$WorkspaceUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Result-state taxonomy
# ---------------------------------------------------------------------------
$FailureResultStates  = @('FAILED', 'TIMEDOUT', 'UPSTREAM_FAILED', 'INTERNAL_ERROR', 'MAXIMUM_CONCURRENT_RUNS_REACHED')
$CancelledResultState = 'CANCELED'
$RunningLifeCycle     = @('RUNNING', 'PENDING', 'BLOCKED', 'QUEUED', 'WAITING_FOR_RETRY')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step { param([string]$Message, [string]$Color = 'Cyan') Write-Host $Message -ForegroundColor $Color }

function Test-DatabricksCli {
    $cli = Get-Command databricks -ErrorAction SilentlyContinue
    if (-not $cli) {
        throw "Databricks CLI not found on PATH. Install the Go-based CLI: https://docs.databricks.com/dev-tools/cli/install.html"
    }
    try { $versionRaw = (& databricks --version 2>&1 | Out-String).Trim() }
    catch { throw "Failed to run 'databricks --version': $($_.Exception.Message)" }

    if ($versionRaw -match 'v?(\d+)\.(\d+)\.(\d+)') {
        $major = [int]$Matches[1]; $minor = [int]$Matches[2]
        if ($major -eq 0 -and $minor -lt 205) {
            throw "Databricks CLI $versionRaw detected. Need the Go-based CLI (>= 0.205). Upgrade: https://docs.databricks.com/dev-tools/cli/install.html"
        }
    }
    Write-Verbose "Databricks CLI: $versionRaw"
    return $versionRaw
}

function Get-CommonArgs {
    $a = New-Object System.Collections.Generic.List[string]
    if ($Profile) { $a.Add('--profile'); $a.Add($Profile) }
    return , $a.ToArray()
}

function Invoke-DatabricksJson {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $allArgs = @($Arguments) + @(Get-CommonArgs) + @('--output', 'json')
    Write-Verbose "databricks $($allArgs -join ' ')"

    $raw = & databricks @allArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "CLI failed (exit $LASTEXITCODE): databricks $($allArgs -join ' ')`n$($raw | Out-String)"
    }
    $text = ($raw | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    try { return $text | ConvertFrom-Json }
    catch { throw "Could not parse CLI JSON. Raw:`n$text" }
}

function Get-Prop {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $null
}

function Get-WorkspaceHost {
    if ($WorkspaceUrl) { return $WorkspaceUrl.TrimEnd('/') }
    if ($env:DATABRICKS_HOST) { return $env:DATABRICKS_HOST.TrimEnd('/') }
    return '(workspace)'
}

function ConvertFrom-EpochMillis {
    param([long]$Millis)
    if ($Millis -le 0) { return $null }
    return [DateTimeOffset]::FromUnixTimeMilliseconds($Millis).ToLocalTime().DateTime
}

function Get-AllJobRuns {
    param([long]$StartTimeFromMillis)

    $runs      = New-Object System.Collections.Generic.List[object]
    $pageToken = $null
    $maxPages  = 50
    $page      = 0

    do {
        $page++
        $args = @('jobs', 'list-runs', '--limit', '100',
                  '--start-time-from', "$StartTimeFromMillis", '--expand-tasks')
        if ($pageToken) { $args += @('--page-token', $pageToken) }

        $resp = Invoke-DatabricksJson -Arguments $args

        $batch     = @()
        $pageToken = $null

        if ($null -eq $resp) { $batch = @() }
        elseif ($resp -is [System.Array]) { $batch = $resp }
        else {
            $batch = Get-Prop $resp 'runs'
            if (-not $batch) { $batch = @() }
            $pageToken = Get-Prop $resp 'next_page_token'
        }

        foreach ($r in $batch) { $runs.Add($r) }

        if ($page -ge $maxPages) {
            Write-Warning "Hit max page count ($maxPages); older runs may be omitted."
            break
        }
    } while ($pageToken)

    return $runs
}

function Get-RunClassification {
    param([object]$Run)

    $state       = Get-Prop $Run 'state'
    $lifeCycle   = Get-Prop $state 'life_cycle_state'
    $resultState = Get-Prop $state 'result_state'
    $message     = Get-Prop $state 'state_message'

    if (-not $resultState) {
        $status = Get-Prop $Run 'status'
        $term   = Get-Prop $status 'termination_details'
        $code   = Get-Prop $term 'code'
        if ($code) { $resultState = $code }
        $lc = Get-Prop $status 'state'
        if (-not $lifeCycle -and $lc) { $lifeCycle = $lc }
    }

    $category = 'OTHER'
    if ($lifeCycle -in $RunningLifeCycle) { $category = 'RUNNING' }
    elseif ($resultState -eq 'SUCCESS')   { $category = 'SUCCESS' }
    elseif ($resultState -eq $CancelledResultState) {
        $category = if ($TreatCancelledAsFailure) { 'FAILED' } else { 'CANCELLED' }
    }
    elseif ($resultState -in $FailureResultStates) { $category = 'FAILED' }

    return [PSCustomObject]@{
        JobId      = Get-Prop $Run 'job_id'
        RunId      = Get-Prop $Run 'run_id'
        JobName    = Get-Prop $Run 'run_name'
        LifeCycle  = $lifeCycle
        Result     = $resultState
        Category   = $category
        StartTime  = ConvertFrom-EpochMillis ([long](Get-Prop $Run 'start_time'))
        EndTime    = ConvertFrom-EpochMillis ([long](Get-Prop $Run 'end_time'))
        DurationMs = [long](Get-Prop $Run 'run_duration')
        Message    = $message
        RunPageUrl = Get-Prop $Run 'run_page_url'
    }
}

function Format-Duration {
    param([long]$Ms)
    if ($Ms -le 0) { return '' }
    $ts = [TimeSpan]::FromMilliseconds($Ms)
    if ($ts.TotalHours -ge 1)   { return ('{0}h {1}m' -f [int]$ts.TotalHours, $ts.Minutes) }
    if ($ts.TotalMinutes -ge 1) { return ('{0}m {1}s' -f [int]$ts.TotalMinutes, $ts.Seconds) }
    return ('{0}s' -f [int]$ts.TotalSeconds)
}

# ---------------------------------------------------------------------------
# Teams Adaptive Card
# ---------------------------------------------------------------------------
function New-TeamsAdaptiveCard {
    param(
        [array]$Failed, [array]$Cancelled, [array]$Running,
        [int]$SuccessCount, [int]$TotalCount,
        [int]$LookbackHours, [string]$WorkspaceHost
    )

    $healthy    = ($Failed.Count -eq 0)
    $themeColor = if ($healthy) { 'Good' } else { 'Attention' }
    $title      = if ($healthy) { "OK  Databricks jobs healthy" } else { "ALERT  Databricks: $($Failed.Count) failed job(s)" }

    $bodyBlocks = New-Object System.Collections.Generic.List[object]
    $bodyBlocks.Add(@{ type='TextBlock'; size='Large'; weight='Bolder'; text=$title; color=$themeColor; wrap=$true })
    $bodyBlocks.Add(@{ type='TextBlock'; isSubtle=$true; spacing='None'; wrap=$true;
                       text=("Window: last {0}h - {1} - {2:yyyy-MM-dd HH:mm}" -f $LookbackHours, $WorkspaceHost, (Get-Date)) })

    $facts = @(
        @{ title='Total runs'; value="$TotalCount" }
        @{ title='Success';    value="$SuccessCount" }
        @{ title='Failed';     value="$($Failed.Count)" }
        @{ title='Cancelled';  value="$($Cancelled.Count)" }
        @{ title='Running';    value="$($Running.Count)" }
    )
    $bodyBlocks.Add(@{ type='FactSet'; facts=$facts })

    if ($Failed.Count -gt 0) {
        $bodyBlocks.Add(@{ type='TextBlock'; weight='Bolder'; text='Failed runs'; separator=$true; spacing='Medium' })
        foreach ($f in ($Failed | Sort-Object EndTime -Descending | Select-Object -First 15)) {
            $sub = "Run $($f.RunId) - ended $('{0:HH:mm}' -f $f.EndTime)"
            if ($f.Message) { $sub += " - $($f.Message)" }
            $bodyBlocks.Add(@{ type='TextBlock'; text="**$($f.JobName)** - $($f.Result)"; wrap=$true; spacing='Small' })
            $bodyBlocks.Add(@{ type='TextBlock'; text=$sub; isSubtle=$true; wrap=$true; spacing='None'; size='Small' })
        }
        if ($Failed.Count -gt 15) {
            $bodyBlocks.Add(@{ type='TextBlock'; text="...and $($Failed.Count - 15) more"; isSubtle=$true; wrap=$true })
        }
    }

    $actions = New-Object System.Collections.Generic.List[object]
    foreach ($f in ($Failed | Sort-Object EndTime -Descending | Select-Object -First 5)) {
        if ($f.RunPageUrl) { $actions.Add(@{ type='Action.OpenUrl'; title="Open: $($f.JobName)"; url=$f.RunPageUrl }) }
    }

    $adaptiveCard = @{
        type='AdaptiveCard'; '$schema'='http://adaptivecards.io/schemas/adaptive-card.json'
        version='1.4'; body=$bodyBlocks
    }
    if ($actions.Count -gt 0) { $adaptiveCard.actions = $actions }

    return @{
        type='message'
        attachments=@(@{ contentType='application/vnd.microsoft.card.adaptive'; content=$adaptiveCard })
    }
}

function Send-TeamsCard {
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][hashtable]$Payload)
    $json = $Payload | ConvertTo-Json -Depth 20 -Compress
    try {
        Invoke-RestMethod -Uri $Url -Method Post -ContentType 'application/json' -Body $json | Out-Null
        Write-Step "Posted summary to Teams." 'Green'
    }
    catch { Write-Warning "Failed to post to Teams: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
function New-HtmlReport {
    param(
        [array]$Failed, [array]$Cancelled, [array]$Running, [array]$AllRows,
        [int]$SuccessCount, [int]$LookbackHours, [string]$WorkspaceHost, [string]$Path
    )
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    function Esc { param([string]$s) if ($null -eq $s) { return '' } [System.Web.HttpUtility]::HtmlEncode($s) }

    $total = $AllRows.Count
    $failN = $Failed.Count; $cancN = $Cancelled.Count; $runN = $Running.Count
    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $statusBadge = if ($failN -eq 0) { '<span class="badge ok">HEALTHY</span>' } else { "<span class=`"badge bad`">$failN FAILED</span>" }

    $rowsHtml = ($AllRows | Sort-Object EndTime -Descending | ForEach-Object {
        $cls = switch ($_.Category) { 'FAILED'{'r-fail'} 'CANCELLED'{'r-cancel'} 'RUNNING'{'r-run'} 'SUCCESS'{'r-ok'} default{'r-other'} }
        $name = if ($_.RunPageUrl) { "<a href=`"$($_.RunPageUrl)`" target=`"_blank`">$(Esc $_.JobName)</a>" } else { Esc $_.JobName }
        @"
<tr class="$cls">
  <td>$name</td>
  <td><span class="pill p-$($_.Category.ToLower())">$($_.Category)</span></td>
  <td>$(Esc $_.Result)</td>
  <td>$('{0:yyyy-MM-dd HH:mm}' -f $_.StartTime)</td>
  <td>$('{0:HH:mm}' -f $_.EndTime)</td>
  <td>$(Format-Duration $_.DurationMs)</td>
  <td class="msg">$(Esc $_.Message)</td>
</tr>
"@
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Databricks Job Health</title>
<style>
  :root { --bg:#0d1117; --card:#161b22; --line:#30363d; --txt:#e6edf3; --sub:#8b949e;
          --ok:#3fb950; --bad:#f85149; --cancel:#d29922; --run:#58a6ff; --other:#8b949e; }
  *{box-sizing:border-box;}
  body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--txt);padding:24px;}
  header{display:flex;align-items:center;gap:16px;margin-bottom:8px;flex-wrap:wrap;}
  h1{font-size:20px;margin:0;}
  .sub{color:var(--sub);font-size:13px;margin-bottom:20px;}
  .badge{padding:4px 12px;border-radius:999px;font-weight:700;font-size:13px;}
  .badge.ok{background:rgba(63,185,80,.15);color:var(--ok);border:1px solid var(--ok);}
  .badge.bad{background:rgba(248,81,73,.15);color:var(--bad);border:1px solid var(--bad);}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px;}
  .c{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;}
  .c .n{font-size:28px;font-weight:700;}
  .c .l{color:var(--sub);font-size:12px;text-transform:uppercase;letter-spacing:.05em;}
  .c.fail .n{color:var(--bad);} .c.ok .n{color:var(--ok);}
  .c.cancel .n{color:var(--cancel);} .c.run .n{color:var(--run);}
  table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px;}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);}
  th{background:#1c2128;color:var(--sub);text-transform:uppercase;font-size:11px;letter-spacing:.05em;}
  tr:last-child td{border-bottom:none;}
  td a{color:var(--run);text-decoration:none;} td a:hover{text-decoration:underline;}
  .msg{color:var(--sub);max-width:320px;}
  .pill{padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;}
  .p-failed{background:rgba(248,81,73,.15);color:var(--bad);}
  .p-success{background:rgba(63,185,80,.15);color:var(--ok);}
  .p-cancelled{background:rgba(210,153,34,.15);color:var(--cancel);}
  .p-running{background:rgba(88,166,255,.15);color:var(--run);}
  .p-other{background:rgba(139,148,158,.15);color:var(--other);}
  tr.r-fail td{background:rgba(248,81,73,.04);}
</style></head>
<body>
  <header><h1>Databricks Job Health</h1>$statusBadge</header>
  <div class="sub">Window: last $LookbackHours h &middot; $(Esc $WorkspaceHost) &middot; generated $generated</div>
  <div class="cards">
    <div class="c"><div class="n">$total</div><div class="l">Total runs</div></div>
    <div class="c ok"><div class="n">$SuccessCount</div><div class="l">Success</div></div>
    <div class="c fail"><div class="n">$failN</div><div class="l">Failed</div></div>
    <div class="c cancel"><div class="n">$cancN</div><div class="l">Cancelled</div></div>
    <div class="c run"><div class="n">$runN</div><div class="l">Running</div></div>
  </div>
  <table>
    <thead><tr><th>Job</th><th>Status</th><th>Result</th><th>Start</th><th>End</th><th>Duration</th><th>Message</th></tr></thead>
    <tbody>
$rowsHtml
    </tbody>
  </table>
</body></html>
"@

    Set-Content -Path $Path -Value $html -Encoding UTF8
    Write-Step "Wrote HTML report: $Path" 'Green'
}

# ===========================================================================
# Main
# ===========================================================================
try {
    Test-DatabricksCli | Out-Null
    $wsHost = Get-WorkspaceHost

    $nowMillis       = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $startFromMillis = $nowMillis - ([int64]$LookbackHours * 3600 * 1000)
    $cutoffLocal     = (Get-Date).AddHours(-$LookbackHours)

    Write-Step "Checking Databricks job runs since $cutoffLocal (last $LookbackHours h)..."
    if ($Profile) { Write-Host "Profile: $Profile" -ForegroundColor DarkGray }

    $rawRuns = Get-AllJobRuns -StartTimeFromMillis $startFromMillis
    Write-Host "Retrieved $($rawRuns.Count) run(s)." -ForegroundColor DarkGray

    $allRows = @(foreach ($r in $rawRuns) { Get-RunClassification -Run $r })

    $failed    = @($allRows | Where-Object Category -eq 'FAILED')
    $cancelled = @($allRows | Where-Object Category -eq 'CANCELLED')
    $running   = @($allRows | Where-Object Category -eq 'RUNNING')
    $success   = @($allRows | Where-Object Category -eq 'SUCCESS')

    Write-Step "`n=== FAILED ($($failed.Count)) ===" 'Red'
    if ($failed.Count -eq 0) {
        Write-Step "No failed runs in the last $LookbackHours h." 'Green'
    } else {
        $failed | Sort-Object EndTime -Descending |
            Format-Table JobName, JobId, RunId, Result,
                @{ N='Ended'; E={ '{0:HH:mm}' -f $_.EndTime } },
                @{ N='Dur';   E={ Format-Duration $_.DurationMs } }, Message -AutoSize -Wrap
    }
    if ($cancelled.Count -gt 0) { Write-Step "Cancelled: $($cancelled.Count)" 'DarkYellow' }
    if ($running.Count   -gt 0) { Write-Step "Running:   $($running.Count)"   'Yellow' }
    Write-Step "Success:   $($success.Count)" 'Green'

    if ($HtmlReportPath) {
        New-HtmlReport -Failed $failed -Cancelled $cancelled -Running $running -AllRows $allRows `
                       -SuccessCount $success.Count -LookbackHours $LookbackHours `
                       -WorkspaceHost $wsHost -Path $HtmlReportPath
    }

    if ($TeamsWebhookUrl) {
        if ($failed.Count -gt 0 -or $AlwaysPostToTeams) {
            $card = New-TeamsAdaptiveCard -Failed $failed -Cancelled $cancelled -Running $running `
                        -SuccessCount $success.Count -TotalCount $allRows.Count `
                        -LookbackHours $LookbackHours -WorkspaceHost $wsHost
            Send-TeamsCard -Url $TeamsWebhookUrl -Payload $card
        } else {
            Write-Host "No failures; skipping Teams post (use -AlwaysPostToTeams to always send)." -ForegroundColor DarkGray
        }
    }

    if ($failed.Count -gt 0) { exit 1 }
    exit 0
}
catch {
    Write-Error $_
    exit 2
}
