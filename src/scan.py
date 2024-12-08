from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING, Any

import boto3
from botocore.exceptions import ClientError
from pydantic import BaseModel, Field, computed_field, model_validator
from rich import print

if TYPE_CHECKING:
    from types_boto3_ecr.client import ECRClient
    from types_boto3_ecr.type_defs import DescribeImageScanFindingsResponseTypeDef


class SeverityCount(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFORMATIONAL: int = 0
    UNDEFINED: int = 0


class Attribute(BaseModel):
    key: str
    value: str


class Finding(BaseModel):
    name: str
    description: str
    uri: str
    severity: str
    attributes: list[Attribute]

    @computed_field
    def package_name(self) -> str:
        for item in self.attributes:
            if item.key == "package_name":
                return item.value
        return "Unknown"

    @computed_field
    def package_version(self) -> str:
        for item in self.attributes:
            if item.key == "package_version":
                return item.value
        return "Unknown"


class ScanResult(BaseModel):
    ignore_list: list[str] | None = Field(None, repr=False)
    scan_completed_at: datetime = Field(..., alias="imageScanCompletedAt")
    source_updated_at: datetime = Field(..., alias="vulnerabilitySourceUpdatedAt")
    severity_counts: SeverityCount = Field(..., alias="findingSeverityCounts")
    findings: list[Finding] = Field(default_factory=list)
    enhanced_findings: list[Finding] = Field(
        default_factory=list, alias="enhancedFindings"
    )

    @model_validator(mode="before")
    @classmethod
    def filter_findings(cls, data: Any) -> Any:
        if ignore_list := data.get("_ignore_list"):
            # Filter out ignored findings
            filtered_findings = []
            filtered_severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFORMATIONAL": 0,
                "UNDEFINED": 0,
            }
            for finding in data.get("findings", []):
                if any(item in finding["name"] for item in ignore_list):
                    continue
                filtered_severity_counts[finding["severity"]] += 1
                filtered_findings.append(finding)
            data["findings"] = filtered_findings
            data["severity_counts"] = filtered_severity_counts
        return data

    @computed_field
    def total_findings(self) -> int:
        return len(self.findings)


def get_scan_findings(
    ecr_client: ECRClient, repository_name: str, image_tag: str
) -> DescribeImageScanFindingsResponseTypeDef | None:
    try:
        return ecr_client.describe_image_scan_findings(
            repositoryName=repository_name,
            imageId={"imageTag": image_tag},
        )
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ScanNotFoundException":
            return None
        raise


def get_image_scan_findings(
    repository_name: str,
    image_tag: str,
    region: str = "us-east-2",
    max_retries: int = 10,
    retry_delay: int = 5,
    ignore_list: list[str] | None = None,
) -> ScanResult:
    """
    Retrieve the security scan findings for a specified ECR image.

    Args:
        repository_name: Name of the ECR repository
        image_tag: Tag of the image to check
        region: AWS region where the repository exists
        max_retries: Maximum number of retry attempts for checking scan status
        retry_delay: Delay in seconds between retry attempts
        ignore_list: List of CVE ids to ignore

    Returns:
        ScanResult: The scan result object

    Raises:
        ClientError: If there's an error accessing ECR
        TimeoutError: If scan results aren't available after max retries
    """
    ecr_client = boto3.client("ecr", region_name=region)

    # Wait for scan to complete
    for attempt in range(max_retries):
        findings = get_scan_findings(ecr_client, repository_name, image_tag)

        if findings is None:
            print(f"Scan not found, attempt {attempt + 1}/{max_retries}")
            time.sleep(retry_delay)
            continue

        scan_status = findings.get("imageScanStatus", {}).get("status")
        match scan_status:
            case "COMPLETE":
                return ScanResult(
                    **findings.get("imageScanFindings", {}),  # type: ignore
                    ignore_list=ignore_list,
                )
            case "FAILED":
                raise RuntimeError(
                    f"Scan failed: {findings['imageScanStatus'].get('description')}"
                )
            case _:
                pass

        print(f"Scan in progress, attempt {attempt + 1}/{max_retries}")
        time.sleep(retry_delay)

    raise TimeoutError("Scan results not available after maximum retries")
