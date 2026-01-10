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

- `--no-color`: Disable color output
- `-v, --verbose`: Verbose output
- `-h, --help`: Help for the command

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