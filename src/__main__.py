import argparse
import json
import os
import sys
import uuid
from pathlib import Path

from rich import print as pprint
from rich.box import SQUARE
from rich.console import Console
from rich.table import Table

from src.constants import (
    SEVERITY_LEVELS,
)
from src.scan import Finding, ScanResult, get_image_scan_findings
from src.utils import generate_markdown_report

MAX_DESCRIPTION_LENGTH = 300


def print_findings_table(scan_result: ScanResult, console: Console) -> None:
    """Print a formatted table of vulnerability findings."""
    pprint(
        f"[bold]Total: {scan_result.total_findings}"
        f" ({scan_result.severity_counts}) [/bold]",
    )
    if scan_result.total_findings:
        table = Table(
            title="ECR Image Scan Findings",
            show_lines=True,
            box=SQUARE,
            expand=True,
        )

        # Add columns
        table.add_column("Severity", style="bold")
        table.add_column("Name", style="dim")
        table.add_column("Package", style="bold")
        table.add_column("Version", style="dim")
        table.add_column("Description")

        # Define severity colors
        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "red3",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFORMATIONAL": "blue",
            "UNDEFINED": "dim",
        }

        # Sort findings by severity level
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFORMATIONAL": 4,
            "UNDEFINED": 5,
        }

        sorted_findings: list[Finding] = sorted(
            scan_result.findings,
            key=lambda x: (
                severity_order.get(x.severity, 999),
                x.package_name,
                x.name,
            ),
        )

        # Add rows
        for finding in sorted_findings:
            table.add_row(
                f"[{severity_colors[finding.severity]}]{finding.severity}[/]",
                finding.name,
                str(finding.package_name),
                str(finding.package_version),
                finding.description[:MAX_DESCRIPTION_LENGTH] + "..."
                if len(finding.description) > MAX_DESCRIPTION_LENGTH
                else finding.description,
            )

        console.print(table)


def scan(
    repository: str,
    tag: str,
    fail_threshold: str = "high",
    ignore_list: str | None = None,
    github: bool = False,
    region: str = "us-east-2",
    max_retries: int = 10,
    retry_delay: int = 5,
) -> None:
    """
    Main function to scan ECR images and check for vulnerabilities

    Args:
        repository: ECR repository name
        tag: Image tag to scan
        fail_threshold: Severity threshold to fail on ('critical', 'high', 'medium',
        'low', 'informational')
        github: Set to False to disable GitHub Actions output variables
        ignore_list: List of vulnerability IDs to ignore

    Raises:
        RuntimeError: If vulnerabilities are found at or above the fail threshold
    """
    threshold_level = SEVERITY_LEVELS[fail_threshold.lower()]

    scan_result: ScanResult = get_image_scan_findings(
        repository_name=repository,
        image_tag=tag,
        ignore_list=ignore_list,
        region=region,
        max_retries=max_retries,
        retry_delay=retry_delay,
        threshold_level=threshold_level,
    )
    print_findings_table(scan_result, Console(force_terminal=True))
    detailed_findings = [i.model_dump() for i in scan_result.findings]

    if github:
        # Set output variables using GitHub Actions workflow commands
        set_output("critical", str(scan_result.severity_counts.CRITICAL))
        set_output("high", str(scan_result.severity_counts.HIGH))
        set_output("medium", str(scan_result.severity_counts.MEDIUM))
        set_output("low", str(scan_result.severity_counts.LOW))
        set_output("informational", str(scan_result.severity_counts.INFORMATIONAL))
        set_output("undefined", str(scan_result.severity_counts.UNDEFINED))
        set_output("total", str(scan_result.total_findings))
        set_output("detailed_findings", json.dumps(detailed_findings, indent=2))
        set_output(
            "markdown_report",
            generate_markdown_report(
                repository=repository,
                tag=tag,
                scan_result=scan_result,
            ),
        )

    if scan_result.failed_findings_count:
        message = (
            f"Found {scan_result.failed_findings_count} vulnerabilities at"
            f" or above the {fail_threshold} threshold"
        )
        if github:
            pprint(message)
            set_output("outcome", "failure")
            return
        raise RuntimeError(message)
    if github:
        set_output("outcome", "success")


def set_output(name: str, value: str) -> None:
    """
    Set an output variable using GitHub Actions workflow commands

    Args:
        name: Name of the output variable
        value: Value to set
    """
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as fh:
        if "\n" in value:
            # Use delimiter syntax for multiline values
            delimiter = uuid.uuid4()
            fh.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            fh.write(f"{name}={value}\n")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for the script.

    Returns:
        Parsed arguments as a Namespace object
    """
    parser = argparse.ArgumentParser(description="Scan ECR images for vulnerabilities")
    parser.add_argument("repository", help="ECR repository name")
    parser.add_argument("tag", help="Image tag to scan")
    parser.add_argument(
        "--fail-threshold",
        default="high",
        choices=[
            "critical",
            "high",
            "medium",
            "low",
            "informational",
            "undefined",
            "none",
        ],
        help="Severity threshold to fail on (default: critical)",
    )
    parser.add_argument(
        "--ignore-list",
        help="Space-separated list of vulnerability IDs to ignore",
    )
    parser.add_argument(
        "--region",
        default="us-east-2",
        help="AWS region to use for scanning (default: us-east-2)",
    )
    parser.add_argument(
        "--github_action",
        action="store_true",
        default=False,
        help="Set to False to disable GitHub Actions output variables",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=10,
        help="Maximum number of retries to check scan status (default: 10)",
    )
    parser.add_argument(
        "--retry-delay",
        type=int,
        default=5,
        help="Delay in seconds between retry attempts (default: 5)",
    )
    return parser.parse_args()


def main() -> None:
    """Parses command line arguments and initiates the scan"""
    args = parse_args()
    scan(
        repository=args.repository,
        tag=args.tag,
        fail_threshold=args.fail_threshold,
        ignore_list=args.ignore_list,
        github=args.github_action,
        region=args.region,
        max_retries=args.max_retries,
        retry_delay=args.retry_delay,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e!s}", file=sys.stderr)
        sys.exit(1)
