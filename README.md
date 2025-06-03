# AWS ECR Security Scanner Action
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Coverage Status](./coverage-badge.svg?dummy=8484744)](./coverage-badge.svg)

A GitHub Action to scan container images in Amazon ECR for security vulnerabilities.
This action provides a way to retrieve ECR automatic scans with direct feedback in a PR, failing builds if serious security issues are detected.

## Features

- 🛡️ Retrieves ECR image scans, checking for security vulnerabilities
- 📊 Provides detailed vulnerability reports
- 🚫 Configurable failure thresholds
- ⏭️ Ability to ignore specific vulnerabilities
- 💬 Automatic PR comments with findings
- 🎨 Rich console output with formatted tables

## Usage

```yaml
- uses: vonsteer/ecr-scanning-action@v1
  with:
    repository: myorg/myimage  # ECR repository name
    tag: latest               # Image tag to scan
    fail_threshold: high      # Optional: Severity level that will cause failure (default: high)
    ignore_list: CVE-2023-1234 CVE-2023-5678  # Optional: CVEs to ignore
    region: us-east-2        # Optional: AWS region (default: us-east-2)
    pr_comment: true         # Optional: Post results as PR comment (default: true)
    max_retries: 10          # Optional: Maximum number of retries for API calls (default: 10)
    retry_delay: 5           # Optional: Delay between retries in seconds (default: 5)
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `repository` | ECR repository name | Yes | - |
| `tag` | Image tag to scan | Yes | - |
| `fail_threshold` | Severity level that will cause failure | No | `critical` |
| `ignore_list` | List of CVE IDs to ignore | No | - |
| `region` | AWS region | No | `us-east-2` |
| `pr_comment` | Post results as PR comment | No | `true` |
| `max_retries` | Maximum number of retries for API calls | No | `10` |
| `retry_delay` | Delay between retries (in seconds) | No | `5` |


### Fail Thresholds

Available threshold levels (from highest to lowest):
- `critical`
- `high`
- `medium`
- `low`
- `informational`
- `none`

## Outputs

| Output | Description |
|--------|-------------|
| `critical` | Number of critical vulnerabilities |
| `high` | Number of high vulnerabilities |
| `medium` | Number of medium vulnerabilities |
| `low` | Number of low vulnerabilities |
| `informational` | Number of informational findings |
| `undefined` | Number of undefined severity findings |
| `total` | Total number of findings |
| `detailed_findings` | JSON object with detailed scan results |

## Example Workflow

```yaml
name: Security Scan

on:
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
      pull-requests: write  # Required for PR comments

    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions
          aws-region: us-east-2

      - uses: vonsteer/ecr-scanning-action@v1
        with:
          repository: myorg/myimage
          tag: latest
          fail_threshold: high
          ignore_list: CVE-2023-1234 CVE-2023-5678
```

## Required AWS Permissions

The action requires the following AWS IAM permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:DescribeImageScanFindings",
                "ecr:DescribeImages",
                "ecr:BatchGetImage"
            ],
            "Resource": "arn:aws:ecr:*:*:repository/*"
        }
    ]
}
```

## Local Usage

You can also use the scanner locally:

```bash
# Install the package
uv pip install .

# Run the scanner
ecr-scan myorg/myimage latest --fail-threshold high --ignore-list CVE-2023-1234
```

## Testing

This project includes a comprehensive testing strategy with unit tests and integration tests:

### Unit Tests

Unit tests use the botocore stubber to mock AWS API interactions:

```bash
# Run all tests
make test

# Run specific tests
make test-only TestECRScanner
```

### Integration Tests

A GitHub workflow (`action-integration-test.yml`) tests the action with actual AWS resources:
1. Pushes a test image to ECR
2. Runs the scanning action against the image
3. Tests both success and failure scenarios
4. Tests the CVE ignore list functionality

This ensures the action works correctly in real-world scenarios.

### Smoke Test

A basic smoke test ensures the package can be imported and executed:

```bash
# Run the smoke test
python tests/smoke_test.py
```

## License

[MIT License](LICENSE)
