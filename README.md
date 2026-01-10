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

## For developers

To build and install locally:

```bash
go build .
gh extension install .
```