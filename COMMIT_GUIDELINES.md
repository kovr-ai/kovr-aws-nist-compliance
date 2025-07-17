# Commit Guidelines for AWS NIST Compliance Checker

## Overview

This project follows strict commit hygiene practices to maintain code quality and ensure meaningful commit history. We use pre-commit hooks and conventional commit format.

## Quick Start

```bash
# One-time setup
./setup-pre-commit.sh

# Before committing, ensure hooks pass
pre-commit run --all-files

# Commit with conventional format
git commit -m "feat: add new security check for S3 versioning"
```

## Conventional Commit Format

All commits must follow this format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types (Required)

- **feat**: New feature or capability
- **fix**: Bug fix
- **docs**: Documentation only changes
- **style**: Code style changes (formatting, whitespace, etc.)
- **refactor**: Code changes that neither fix bugs nor add features
- **test**: Adding or modifying tests
- **chore**: Maintenance tasks, dependency updates
- **perf**: Performance improvements
- **ci**: CI/CD configuration changes
- **build**: Build system or external dependency changes
- **revert**: Reverting a previous commit

### Scope (Optional)

The scope provides additional context:

- `iam`, `s3`, `ec2`, `rds`, `vpc` - AWS service-specific changes
- `checks` - Security check implementations
- `reports` - Report generation changes
- `cli` - Command-line interface changes
- `config` - Configuration changes

### Subject (Required)

- Use imperative mood ("add" not "added")
- Don't capitalize first letter
- No period at the end
- Maximum 50 characters

### Body (Optional but Recommended)

- Explain what and why, not how
- Wrap at 72 characters
- Separate from subject with blank line
- Use bullet points for multiple items

### Footer (Optional)

- Reference issues: `Fixes #123`, `Closes #456`
- Breaking changes: `BREAKING CHANGE: description`

## Examples

### Simple Feature Addition

```
feat(s3): add bucket versioning compliance check

Add CHECK-016 to verify S3 buckets have versioning enabled.
Maps to NIST 800-53 control CP-9 for data recovery.

Fixes #23
```

### Bug Fix with Details

```
fix(iam): correct access key age calculation

The previous implementation incorrectly calculated key age
when keys were created in different timezones. Now uses
UTC consistently for all date comparisons.

- Use timezone-aware datetime objects
- Convert all timestamps to UTC before comparison
- Add proper error handling for missing timestamps

Fixes #45
```

### Documentation Update

```
docs: update README with pre-commit setup instructions

Add section explaining how to set up and use pre-commit
hooks for maintaining code quality.
```

### Refactoring

```
refactor(checks): extract common pagination logic

Move repeated pagination code into shared utility function
to reduce duplication across security checks.

- Create paginate_aws_resources() helper
- Update all checks to use new helper
- Improve error handling in pagination
```

### Breaking Change

```
feat(cli): change report output directory structure

BREAKING CHANGE: Reports are now organized in subdirectories
by date (YYYY-MM-DD) instead of flat structure. Users need
to update any automation expecting the old structure.

New structure:
  reports/2024-01-15/compliance_results.csv
  reports/2024-01-15/nist_report.md

Old structure:
  reports/compliance_results_20240115.csv
  reports/nist_report_20240115.md
```

## Pre-commit Hooks

The following checks run automatically:

### File Checks

- No trailing whitespace
- Files end with newline
- No large files (>1MB)
- No AWS credentials
- No private keys

### Python Code

- **Black** formatting (100 char lines)
- **isort** import sorting
- **flake8** linting
- **mypy** type checking
- **bandit** security scanning

### Other

- **shellcheck** for bash scripts
- **markdownlint** for markdown files
- **gitlint** for commit messages

## Commit Workflow

1. **Make Changes**

   ```bash
   # Edit files
   vim src/aws_connector.py
   ```

2. **Stage Changes**

   ```bash
   git add src/aws_connector.py
   ```

3. **Commit (Hooks Run Automatically)**

   ```bash
   git commit
   # Opens editor with commit template
   ```

4. **If Hooks Fail**

   ```bash
   # Fix issues
   black src/aws_connector.py

   # Re-stage
   git add src/aws_connector.py

   # Retry commit
   git commit
   ```

## Commit Message Tips

### DO

- Write clear, concise messages
- Explain the why, not just what
- Reference related issues
- Use present tense, imperative mood
- Break up large changes into logical commits

### DON'T

- Don't commit commented-out code
- Don't mix unrelated changes
- Don't use generic messages like "fix bug"
- Don't commit sensitive data
- Don't skip pre-commit hooks

## Handling Hook Failures

If pre-commit hooks fail:

1. **Read the Error Output**: Each tool provides specific feedback
2. **Auto-fix When Possible**: Some tools can fix issues automatically

   ```bash
   black src/aws_connector.py
   isort src/aws_connector.py
   ```

3. **Manual Fixes**: Address linting errors, type hints, etc.
4. **Re-run Hooks**: `pre-commit run --all-files`

## Skipping Hooks (Emergency Only)

In rare cases where you need to skip hooks:

```bash
git commit --no-verify -m "fix: emergency production fix"
```

**Note**: This should be avoided. If used, create a follow-up commit to fix any issues.

## Commit History Best Practices

1. **Atomic Commits**: Each commit should be a single logical change
2. **Clean History**: Use interactive rebase to clean up before pushing
3. **Meaningful Messages**: Future developers (including you) will thank you
4. **Regular Commits**: Commit often, push less often

## Questions?

If you encounter issues with commit hooks or need clarification on guidelines, check:

1. The error output from pre-commit
2. Tool-specific configuration in `.pre-commit-config.yaml`
3. Individual tool configs (`pyproject.toml`, `.flake8`, etc.)
