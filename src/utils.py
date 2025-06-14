from __future__ import annotations

from typing import TYPE_CHECKING

from py_markdown_table.markdown_table import markdown_table

from src.constants import (
    DETAILED_FINDINGS_SECTION,
    FAILURE_FOOTER,
    HEADER,
    IGNORED_NOT_FOUND,
    IGNORED_SECTION,
    LEVEL_EMOJI_MAPPING,
    MAX_DESCRIPTION_LENGTH,
    NEUTRAL_FOOTER,
    SUCCESS_FOOTER,
    SUMMARY_SECTION,
)

if TYPE_CHECKING:
    from src.scan import ScanResult


def format_description(description: str) -> str:
    """
    Format the description to ensure it does not exceed the maximum length.

    Args:
        description: The description string to format.

    Returns:
        A formatted description string truncated to MAX_DESCRIPTION_LENGTH.
    """
    if len(description) > MAX_DESCRIPTION_LENGTH:
        return description[:MAX_DESCRIPTION_LENGTH] + "..."
    return description


def parse_ignore_list(ignore_list_string: str | None) -> list[str] | None:
    """
    Parse the ignore list from a string into a list of strings.

    Args:
        ignore_list: A string containing comma-separated values or None.

    Returns:
        A list of strings if ignore_list is provided, otherwise None.
    """
    if not ignore_list_string:
        return None
    ignore_list = ignore_list_string.strip()
    if "," in ignore_list_string:
        ignore_list = ignore_list_string.split(",")
    elif " " in ignore_list_string:
        ignore_list = ignore_list_string.split(" ")
    else:
        ignore_list = [ignore_list_string]
    return ignore_list


def generate_markdown_report(
    repository: str,
    tag: str,
    scan_result: ScanResult,
) -> str:
    """
    Generate a markdown report from the scan results.
    Args:
        repository: The name of the ECR repository.
        tag: The tag of the image scanned.
        scan_result: The result of the scan containing findings and metadata.
    Returns:
        A markdown formatted string report summarizing the scan results.
    """
    result_strings = [
        HEADER.format(
            repository=repository,
            tag=tag,
        )
    ]

    if scan_result.total_findings:
        summary_data = [
            {
                "": LEVEL_EMOJI_MAPPING.get(severity),
                "Severity": severity,
                "Count": count,
            }
            for severity, count in scan_result.severity_counts
        ]
        markdown = (
            markdown_table(summary_data)
            .set_params(row_sep="markdown", quote=False)
            .get_markdown()
        )
        result_strings.append(
            SUMMARY_SECTION.format(summary=markdown, total=scan_result.total_findings)
        )

        detailed_findings_data = [
            {
                "Name": finding.name,
                "Severity": finding.severity,
                "Package": finding.package_name,
                "Version": finding.package_version,
                "Description": format_description(finding.description),
            }
            for finding in scan_result.findings
        ]
        markdown = (
            markdown_table(detailed_findings_data)
            .set_params(row_sep="markdown", quote=False)
            .get_markdown()
        )
        result_strings.append(
            DETAILED_FINDINGS_SECTION.format(detailed_findings=markdown)
        )

    if scan_result.ignore_list:
        markdown = ""
        if scan_result.ignored_findings:
            ignored_data = [
                {
                    "Name": finding.name,
                    "Severity": finding.severity,
                    "Package": finding.package_name,
                    "Version": finding.package_version,
                    "Description": format_description(finding.description),
                }
                for finding in scan_result.ignored_findings
            ]
            markdown = (
                markdown_table(ignored_data)
                .set_params(row_sep="markdown", quote=False)
                .get_markdown()
            )
        ignored_section = IGNORED_SECTION.format(ignored_findings=markdown)
        found_ignored_cves = [f.name for f in scan_result.ignored_findings]
        if any(
            ignored_cve not in found_ignored_cves
            for ignored_cve in scan_result.ignore_list
        ):
            ignored_section += IGNORED_NOT_FOUND
        result_strings.append(ignored_section)

    if scan_result.failed_findings_count:
        footer = FAILURE_FOOTER
    elif scan_result.total_findings == 0 and not scan_result.ignore_list:
        footer = SUCCESS_FOOTER
    else:
        footer = NEUTRAL_FOOTER
    result_strings.append(footer)

    return "\n".join(result_strings)
