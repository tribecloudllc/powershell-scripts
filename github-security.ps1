param(
    [Parameter(Mandatory=$true)]
    [string]$RepoPath
)

$workflows = Get-ChildItem -Path "$RepoPath/.github/workflows" -Filter "*.yml" -Recurse -ErrorAction SilentlyContinue
if (-not $workflows) {
    $workflows = Get-ChildItem -Path "$RepoPath/.github/workflows" -Filter "*.yaml" -Recurse -ErrorAction SilentlyContinue
}

if (-not $workflows) {
    Write-Host "No workflow files found in $RepoPath/.github/workflows" -ForegroundColor Red
    exit 1
}

$findings = @()

foreach ($file in $workflows) {
    $content = Get-Content $file.FullName -Raw
    $lines   = Get-Content $file.FullName

    # CRITICAL 1: Missing permissions block
    if ($content -notmatch '(?m)^permissions:' -and $content -notmatch '^\s{2,4}permissions:') {
        $findings += [PSCustomObject]@{
            Severity = "CRITICAL"
            File     = $file.Name
            Line     = "-"
            Issue    = "No explicit 'permissions:' block found"
        }
    }

    # CRITICAL 2: ${{ }} expressions inside run: blocks
    $inRunBlock = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s+run:') { $inRunBlock = $true }
        elseif ($inRunBlock -and $line -match '^\s+\w+:' -and $line -notmatch '^\s+\|') { $inRunBlock = $false }

        if ($inRunBlock -and $line -match '\$\{\{.*\}\}') {
            $findings += [PSCustomObject]@{
                Severity = "CRITICAL"
                File     = $file.Name
                Line     = ($i + 1)
                Issue    = "Expression in run block (injection risk): " + $line.Trim()
            }
        }
    }

    # CRITICAL 3: Unsanitized writes to GITHUB_ENV
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '\$GITHUB_ENV' -and $lines[$i] -match '\$\{\{') {
            $findings += [PSCustomObject]@{
                Severity = "CRITICAL"
                File     = $file.Name
                Line     = ($i + 1)
                Issue    = "Unsanitized expression written to GITHUB_ENV: " + $lines[$i].Trim()
            }
        }
    }

    # CRITICAL 4: pull_request_target trigger
    if ($content -match 'pull_request_target') {
        $lineNum = ($lines | Select-String 'pull_request_target' | Select-Object -First 1).LineNumber
        $findings += [PSCustomObject]@{
            Severity = "CRITICAL"
            File     = $file.Name
            Line     = $lineNum
            Issue    = "Unsafe trigger: pull_request_target detected"
        }
    }

    # CRITICAL 5: Potential committed secrets
    $secretPatterns = @(
        'ghp_[A-Za-z0-9]{36}',
        'AKIA[0-9A-Z]{16}',
        'AIza[0-9A-Za-z\-_]{35}',
        'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        'password\s*[:=]\s*\S+'
    )
    foreach ($pattern in $secretPatterns) {
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match $pattern) {
                $findings += [PSCustomObject]@{
                    Severity = "CRITICAL"
                    File     = $file.Name
                    Line     = ($i + 1)
                    Issue    = "Possible secret (pattern: $pattern): " + $lines[$i].Trim()
                }
            }
        }
    }

    # HIGH: Actions not pinned to commit SHA
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s+uses:\s+(.+)') {
            $action = $matches[1].Trim()
            if ($action -notmatch '^\./' -and $action -notmatch '@[a-f0-9]{40}$') {
                $findings += [PSCustomObject]@{
                    Severity = "HIGH"
                    File     = $file.Name
                    Line     = ($i + 1)
                    Issue    = "Action not pinned to commit SHA: $action"
                }
            }
        }
    }
}

# Output
if ($findings.Count -eq 0) {
    Write-Host "`nNo issues found." -ForegroundColor Green
} else {
    Write-Host "`nFound $($findings.Count) issue(s):" -ForegroundColor Yellow
    $findings | Sort-Object Severity, File, Line | Format-Table -AutoSize -Wrap

    $critical = ($findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $high     = ($findings | Where-Object { $_.Severity -eq "HIGH" }).Count
    Write-Host "Summary: CRITICAL=$critical  HIGH=$high" -ForegroundColor Cyan
}
