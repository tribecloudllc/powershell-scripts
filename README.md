# githubsec.ps1

PowerShell script that scans GitHub Actions workflow files for common security misconfigurations and generates a self-contained HTML report.

## Checks

| # | Severity | What it detects |
|---|----------|-----------------|
| 1 | CRITICAL | Missing `permissions:` block (workflow or job level) |
| 2 | CRITICAL | `${{ }}` expressions inside `run:` blocks (script injection) |
| 3 | CRITICAL | Unsanitized values written to `$GITHUB_ENV` |
| 4 | CRITICAL | `pull_request_target` trigger usage |
| 5 | CRITICAL | Hardcoded secrets (GitHub PAT, AWS key, GCP key, JWT, passwords) |
| 6 | HIGH     | Third-party actions not pinned to a full commit SHA |

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- Repository cloned locally (reads `.github/workflows/*.yml` / `*.yaml`)
- No external dependencies

## Usage

```powershell
# Basic — report saved as workflow-security-report.html in current directory
.\githubsec-html.ps1 -RepoPath "C:\repos\my-repo"

# Custom output path
.\githubsec-html.ps1 -RepoPath "C:\repos\my-repo" -OutputFile "C:\reports\my-repo-security.html"
```

The report opens automatically in the default browser after generation.

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-RepoPath` | Yes | — | Path to the root of the cloned repository |
| `-OutputFile` | No | `workflow-security-report.html` | Output path for the HTML report |

## Report

The HTML report includes:

- **Status banner** — `ACTION REQUIRED` / `REVIEW NEEDED` / `PASSED`
- **Stats bar** — number of workflows scanned, total findings, critical and high counts
- **Findings table** — severity, file name, line number, issue description, and recommended fix
- Self-contained single file, no external dependencies, dark theme

## Examples

### No issues found

```
Report saved to: workflow-security-report.html
```

Status banner shows **PASSED** in green.

### Issues found

```
Report saved to: workflow-security-report.html
```

Status banner shows **ACTION REQUIRED** in red. Each finding includes a recommended fix inline in the table.

## Remediation Quick Reference

**Missing permissions block**
```yaml
permissions: read-all  # top-level default
jobs:
  build:
    permissions:
      contents: read
      packages: write
```

**Expression in run: block**
```yaml
# Before (unsafe)
- run: echo "${{ github.event.pull_request.title }}"

# After (safe)
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"
```

**Action not pinned to SHA**
```yaml
# Before
uses: actions/checkout@v4

# After
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

**Committed secret**
```yaml
# Before
env:
  TOKEN: ghp_xxxxxxxxxxxx

# After
env:
  TOKEN: ${{ secrets.MY_TOKEN }}
```
> After removing a secret from the workflow file, purge it from git history using [`git filter-repo`](https://github.com/newren/git-filter-repo) and rotate/revoke the credential immediately.

## License

MIT
