# gh-list-security-advisories

A GitHub CLI Extension to list security advisories for all repositories of a specified owner.

## Installation

```bash
gh extension install suer/gh-list-security-advisories
```

to upgrade

```bash
gh extension upgrade suer/gh-list-security-advisories
```

## Usage

```bash
gh list-security-advisories <owner> [<owner>...]
```

For example, for a single owner:

```bash
gh list-security-advisories octocat
```

For multiple owners:

```bash
gh list-security-advisories octocat github
```

This will display all security advisories for all repositories owned by the specified owner(s). When multiple owners are specified, they are processed in parallel for faster results.

### Flags

- `-e, --exclude`: Exclude repositories containing the specified string (can be used multiple times)
- `-l, --limit`: Max number of vulnerability alerts to fetch per repository (default: 100)
- `-s, --severity`: Filter by severity (CRITICAL, HIGH, MODERATE, LOW) (can be used multiple times)
- `--show`: Show detailed information for a specific GHSA ID
- `--no-color`: Disable color output
- `-v, --verbose`: Verbose output
- `-h, --help`: Help for the command

### Examples

Exclude specific repositories:

```bash
# Exclude repositories containing "test" in their name
gh list-security-advisories octocat -e test

# Exclude multiple repositories
gh list-security-advisories octocat -e test -e demo

# Exclude repositories by full name
gh list-security-advisories octocat -e octocat/private-repo
```

Limit the number of alerts per repository:

```bash
# Fetch only the first 10 alerts per repository
gh list-security-advisories octocat -l 10

# Combine with other options
gh list-security-advisories octocat -l 50 -e test
```

Filter by severity:

```bash
# Show only CRITICAL advisories
gh list-security-advisories octocat -s CRITICAL

# Show HIGH and CRITICAL advisories
gh list-security-advisories octocat -s HIGH -s CRITICAL

# Combine with other options
gh list-security-advisories octocat -s CRITICAL -s HIGH -e test
```

Show detailed advisory information:

```bash
# Show details for a specific GHSA ID
gh list-security-advisories --show GHSA-xxxx-xxxx-xxxx

# Disable color in the output
gh list-security-advisories --show GHSA-xxxx-xxxx-xxxx --no-color
```

## Output Format

The output shows security advisories grouped by repository:

```
# repository-name
GHSA-xxxx-xxxx-xxxx CRITICAL   2024-01-01 Vulnerability summary
GHSA-yyyy-yyyy-yyyy HIGH       2024-01-15 Another vulnerability
```

Severity levels are color-coded:
- **CRITICAL**: Red (bold)
- **HIGH**: Red
- **MODERATE**: Yellow
- **LOW**: Green

### Show option output

When using the `--show` option, detailed information is displayed:

```
GHSA ID: GHSA-xxxx-xxxx-xxxx
Severity: CRITICAL
Summary: Vulnerability summary
Published: 2024-01-01T00:00:00Z
Updated: 2024-01-15T00:00:00Z
URL: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx

Description:
Detailed description of the vulnerability...

Identifiers:
  GHSA: GHSA-xxxx-xxxx-xxxx
  CVE: CVE-2024-12345

References:
  - https://example.com/advisory
  - https://example.com/patch

Affected Packages:
  - package-name (ECOSYSTEM)
    Vulnerable: >= 1.0.0, < 1.2.3
    Patched: 1.2.3
```

## For developers

To build and install locally:

```bash
go build .
gh extension install .
```