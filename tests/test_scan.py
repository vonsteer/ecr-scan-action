import os
from datetime import datetime
from typing import Any
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from src.scan import Finding, ScanResult, get_image_scan_findings


@pytest.fixture()
def scan_findings_response_ignore() -> dict[str, Any]:
    return {
        "imageScanStatus": {"status": "COMPLETE"},
        "imageScanFindings": {
            "imageScanCompletedAt": datetime.now(),
            "vulnerabilitySourceUpdatedAt": datetime.now(),
            "findingSeverityCounts": {
                "CRITICAL": 2,
                "HIGH": 1,
            },
            "findings": [
                {
                    "name": "CVE-2023-1111",
                    "description": "This finding should be ignored",
                    "uri": "https://nvd.nist.gov/vuln/detail/CVE-2023-1111",
                    "severity": "CRITICAL",
                    "attributes": [
                        {"key": "package_name", "value": "package1"},
                        {"key": "package_version", "value": "1.0.0"},
                    ],
                },
                {
                    "name": "CVE-2023-2222",
                    "description": "This finding should NOT be ignored",
                    "uri": "https://nvd.nist.gov/vuln/detail/CVE-2023-2222",
                    "severity": "CRITICAL",
                    "attributes": [
                        {"key": "package_name", "value": "package2"},
                        {"key": "package_version", "value": "2.0.0"},
                    ],
                },
                {
                    "name": "CVE-2023-3333",
                    "description": "This finding should be ignored",
                    "uri": "https://nvd.nist.gov/vuln/detail/CVE-2023-3333",
                    "severity": "HIGH",
                    "attributes": [
                        {"key": "package_name", "value": "package3"},
                        {"key": "package_version", "value": "3.0.0"},
                    ],
                },
            ],
        },
    }


class TestECRScanner:
    """Tests for the ECR scanning functionality"""

    def setup_method(self):
        # Create a boto3 client and stubber for testing
        self.ecr_client = boto3.client("ecr", region_name="us-east-2")
        self.stubber = Stubber(self.ecr_client)

    def test_get_image_scan_findings_success(self):
        """Test successful retrieval of scan findings"""
        # Mock successful response data
        scan_findings_response = {
            "imageScanStatus": {"status": "COMPLETE"},
            "imageScanFindings": {
                "imageScanCompletedAt": datetime.now(),
                "vulnerabilitySourceUpdatedAt": datetime.now(),
                "findingSeverityCounts": {
                    "CRITICAL": 1,
                    "HIGH": 2,
                    "MEDIUM": 3,
                    "LOW": 4,
                    "INFORMATIONAL": 5,
                    "UNDEFINED": 0,
                },
                "findings": [
                    {
                        "name": "CVE-2023-1234",
                        "description": "Test vulnerability 1",
                        "uri": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                        "severity": "CRITICAL",
                        "attributes": [
                            {"key": "package_name", "value": "test-package"},
                            {"key": "package_version", "value": "1.0.0"},
                        ],
                    },
                    {
                        "name": "CVE-2023-5678",
                        "description": "Test vulnerability 2",
                        "uri": "https://nvd.nist.gov/vuln/detail/CVE-2023-5678",
                        "severity": "HIGH",
                        "attributes": [
                            {"key": "package_name", "value": "another-package"},
                            {"key": "package_version", "value": "2.0.0"},
                        ],
                    },
                ],
            },
        }

        # Add expected API call and response to the stubber
        repository_name = "test-repo"
        image_tag = "latest"
        self.stubber.add_response(
            "describe_image_scan_findings",
            scan_findings_response,
            {"repositoryName": repository_name, "imageId": {"imageTag": image_tag}},
        )

        # Activate the stubber
        with self.stubber:
            # Call the function with the stubbed client
            with patch("src.scan.boto3.client", return_value=self.ecr_client):
                result = get_image_scan_findings(
                    repository_name=repository_name,
                    image_tag=image_tag,
                    max_retries=1,
                    retry_delay=0,
                )

                # Verify the result
                assert isinstance(result, ScanResult)
                assert result.total_findings == 2
                assert result.severity_counts.CRITICAL == 1
                assert result.severity_counts.HIGH == 2
                assert len(result.findings) == 2
                assert result.findings[0].name == "CVE-2023-1234"

        # Verify that all expected API calls were made
        self.stubber.assert_no_pending_responses()

    def test_get_image_scan_findings_in_progress(self):
        """Test handling of scan in progress"""
        repository_name = "test-repo"
        image_tag = "latest"

        # First response: IN_PROGRESS
        in_progress_response = {
            "imageScanStatus": {"status": "IN_PROGRESS"},
        }
        self.stubber.add_response(
            "describe_image_scan_findings",
            in_progress_response,
            {"repositoryName": repository_name, "imageId": {"imageTag": image_tag}},
        )

        # Second response: COMPLETE
        complete_response = {
            "imageScanStatus": {"status": "COMPLETE"},
            "imageScanFindings": {
                "imageScanCompletedAt": datetime.now(),
                "vulnerabilitySourceUpdatedAt": datetime.now(),
                "findingSeverityCounts": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 1,
                    "LOW": 0,
                    "INFORMATIONAL": 0,
                    "UNDEFINED": 0,
                },
                "findings": [
                    {
                        "name": "CVE-2023-9999",
                        "description": "Test vulnerability",
                        "uri": "https://nvd.nist.gov/vuln/detail/CVE-2023-9999",
                        "severity": "MEDIUM",
                        "attributes": [
                            {"key": "package_name", "value": "test-package"},
                            {"key": "package_version", "value": "1.0.0"},
                        ],
                    }
                ],
            },
        }
        self.stubber.add_response(
            "describe_image_scan_findings",
            complete_response,
            {"repositoryName": repository_name, "imageId": {"imageTag": image_tag}},
        )

        # Activate the stubber
        with self.stubber:
            # Call the function with the stubbed client
            with patch("src.scan.boto3.client", return_value=self.ecr_client):
                result = get_image_scan_findings(
                    repository_name=repository_name,
                    image_tag=image_tag,
                    max_retries=2,
                    retry_delay=0,
                )

                # Verify the result
                assert isinstance(result, ScanResult)
                assert result.total_findings == 1
                assert result.severity_counts.MEDIUM == 1

        # Verify that all expected API calls were made
        self.stubber.assert_no_pending_responses()

    def test_get_image_scan_findings_failed(self):
        """Test handling of failed scan"""
        repository_name = "test-repo"
        image_tag = "latest"

        # Response: FAILED
        failed_response = {
            "imageScanStatus": {
                "status": "FAILED",
                "description": "Scan failed for some reason",
            },
        }
        self.stubber.add_response(
            "describe_image_scan_findings",
            failed_response,
            {"repositoryName": repository_name, "imageId": {"imageTag": image_tag}},
        )

        # Activate the stubber
        with self.stubber:
            # Call the function with the stubbed client
            with patch("src.scan.boto3.client", return_value=self.ecr_client):
                with pytest.raises(RuntimeError, match="Scan failed:"):
                    get_image_scan_findings(
                        repository_name=repository_name,
                        image_tag=image_tag,
                        max_retries=1,
                        retry_delay=0,
                    )

        # Verify that all expected API calls were made
        self.stubber.assert_no_pending_responses()

    def test_scan_not_found(self):
        """Test handling of scan not found"""
        repository_name = "test-repo"
        image_tag = "latest"

        self.stubber.add_client_error(
            "describe_image_scan_findings",
            service_error_code="ScanNotFoundException",
            service_message="Requested scan cannot be found",
            http_status_code=404,
            expected_params={
                "repositoryName": repository_name,
                "imageId": {"imageTag": image_tag},
            },
        )

        # Add a successful response for the retry
        success_response = {
            "imageScanStatus": {"status": "COMPLETE"},
            "imageScanFindings": {
                "imageScanCompletedAt": datetime.now(),
                "vulnerabilitySourceUpdatedAt": datetime.now(),
                "findingSeverityCounts": {},
                "findings": [],
            },
        }
        self.stubber.add_response(
            "describe_image_scan_findings",
            success_response,
            {"repositoryName": repository_name, "imageId": {"imageTag": image_tag}},
        )

        # Activate the stubber
        with self.stubber:
            # Call the function with the stubbed client
            with patch("src.scan.boto3.client", return_value=self.ecr_client):
                result = get_image_scan_findings(
                    repository_name=repository_name,
                    image_tag=image_tag,
                    max_retries=2,
                    retry_delay=0,
                )

                # Verify the result
                assert isinstance(result, ScanResult)
                assert result.total_findings == 0

        # Verify that all expected API calls were made
        self.stubber.assert_no_pending_responses()

    def test_timeout_error(self):
        """Test handling of timeout when scan never completes"""
        repository_name = "test-repo"
        image_tag = "latest"

        # Add multiple IN_PROGRESS responses
        in_progress_response = {
            "imageScanStatus": {"status": "IN_PROGRESS"},
        }

        # Add the response multiple times
        for _ in range(3):
            self.stubber.add_response(
                "describe_image_scan_findings",
                in_progress_response,
                {"repositoryName": repository_name, "imageId": {"imageTag": image_tag}},
            )

        # Activate the stubber
        with self.stubber:
            # Call the function with the stubbed client
            with patch("src.scan.boto3.client", return_value=self.ecr_client):
                with pytest.raises(TimeoutError, match="Scan results not available"):
                    get_image_scan_findings(
                        repository_name=repository_name,
                        image_tag=image_tag,
                        max_retries=3,
                        retry_delay=0,
                    )

        # Verify that all expected API calls were made
        self.stubber.assert_no_pending_responses()

    def test_ignore_list_filtering_commas(
        self, scan_findings_response_ignore: dict[str, Any]
    ) -> None:
        """Test that vulnerabilities in the ignore list are filtered out"""
        repository_name = "test-repo"
        image_tag = "latest"

        self.stubber.add_response(
            "describe_image_scan_findings",
            scan_findings_response_ignore,
            {"repositoryName": repository_name, "imageId": {"imageTag": image_tag}},
        )

        # Activate the stubber
        with self.stubber:
            # Call the function with the stubbed client and ignore list
            ignore_list = "CVE-2023-1111,CVE-2023-3333"
            with patch("src.scan.boto3.client", return_value=self.ecr_client):
                result = get_image_scan_findings(
                    repository_name=repository_name,
                    image_tag=image_tag,
                    max_retries=1,
                    retry_delay=0,
                    ignore_list=ignore_list,
                )

                # Verify that only the non-ignored finding is present
                assert isinstance(result, ScanResult)
                assert result.total_findings == 1
                assert result.severity_counts.CRITICAL == 1
                assert result.severity_counts.HIGH == 0
                assert len(result.findings) == 1
                assert result.findings[0].name == "CVE-2023-2222"

    def test_ignore_list_filtering_single(
        self, scan_findings_response_ignore: dict[str, Any]
    ) -> None:
        """Test that vulnerabilities in the ignore list are filtered out"""
        repository_name = "test-repo"
        image_tag = "latest"
        self.stubber.add_response(
            "describe_image_scan_findings",
            scan_findings_response_ignore,
            {"repositoryName": repository_name, "imageId": {"imageTag": image_tag}},
        )

        # Activate the stubber
        with self.stubber:
            # Call the function with the stubbed client and ignore list
            ignore_list = "CVE-2023-1111"
            with patch("src.scan.boto3.client", return_value=self.ecr_client):
                result = get_image_scan_findings(
                    repository_name=repository_name,
                    image_tag=image_tag,
                    max_retries=1,
                    retry_delay=0,
                    ignore_list=ignore_list,
                )

                # Verify that only the non-ignored finding is present
                assert isinstance(result, ScanResult)
                assert result.total_findings == 2
                assert result.severity_counts.CRITICAL == 1
                assert result.severity_counts.HIGH == 1
                assert len(result.findings) == 2
                assert result.findings[0].name == "CVE-2023-2222"
                assert result.findings[1].name == "CVE-2023-3333"

    def test_ignore_list_filtering_spaces(
        self, scan_findings_response_ignore: dict[str, Any]
    ) -> None:
        """Test that vulnerabilities in the ignore list are filtered out"""
        repository_name = "test-repo"
        image_tag = "latest"

        self.stubber.add_response(
            "describe_image_scan_findings",
            scan_findings_response_ignore,
            {"repositoryName": repository_name, "imageId": {"imageTag": image_tag}},
        )

        # Activate the stubber
        with self.stubber:
            # Call the function with the stubbed client and ignore list
            ignore_list = "CVE-2023-1111 CVE-2023-3333"
            with patch("src.scan.boto3.client", return_value=self.ecr_client):
                result = get_image_scan_findings(
                    repository_name=repository_name,
                    image_tag=image_tag,
                    max_retries=1,
                    retry_delay=0,
                    ignore_list=ignore_list,
                )

                # Verify that only the non-ignored finding is present
                assert isinstance(result, ScanResult)
                assert result.total_findings == 1
                assert result.severity_counts.CRITICAL == 1
                assert result.severity_counts.HIGH == 0
                assert len(result.findings) == 1
                assert result.findings[0].name == "CVE-2023-2222"


@patch.dict(os.environ, {"GITHUB_OUTPUT": "/dev/null"})
class TestScanCommand:
    """Tests for the scan command functionality"""

    @patch("src.__main__.get_image_scan_findings")
    @patch("src.__main__.set_output")
    @patch("src.__main__.print_findings_table")
    def test_scan_no_vulnerabilities(self, mock_print, mock_set_output, mock_scan):
        """Test scan command with no vulnerabilities"""
        from src.__main__ import scan as scan_command

        # Mock the scan result
        mock_scan.return_value = ScanResult.model_validate(
            {
                "imageScanCompletedAt": datetime.now(),
                "vulnerabilitySourceUpdatedAt": datetime.now(),
                "findingSeverityCounts": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFORMATIONAL": 0,
                    "UNDEFINED": 0,
                },
                "findings": [],
            }
        )

        # Run the scan command
        scan_command(
            repository="test-repo", tag="latest", fail_threshold="critical", github=True
        )

        # Verify mock calls
        mock_scan.assert_called_once()
        assert mock_set_output.call_count >= 8
        # Verify successful outcome
        mock_set_output.assert_any_call("outcome", "success")

    @patch("src.__main__.get_image_scan_findings")
    @patch("src.__main__.set_output")
    @patch("src.__main__.print_findings_table")
    def test_scan_with_critical_vulnerabilities(
        self, mock_print, mock_set_output, mock_scan
    ):
        """Test scan command with critical vulnerabilities"""
        from src.__main__ import scan as scan_command

        # Mock the scan result with critical vulnerabilities
        mock_scan.return_value = ScanResult.model_validate(
            {
                "imageScanCompletedAt": datetime.now(),
                "vulnerabilitySourceUpdatedAt": datetime.now(),
                "findingSeverityCounts": {
                    "CRITICAL": 2,
                    "HIGH": 1,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFORMATIONAL": 0,
                    "UNDEFINED": 0,
                },
                "findings": [
                    {
                        "name": "CVE-2023-1234",
                        "description": "Critical vulnerability",
                        "uri": "https://example.com/CVE-2023-1234",
                        "severity": "CRITICAL",
                        "attributes": [
                            {"key": "package_name", "value": "vulnerable-package"},
                            {"key": "package_version", "value": "1.0.0"},
                        ],
                    }
                ],
            }
        )

        # Run the scan command
        scan_command(
            repository="test-repo", tag="latest", fail_threshold="critical", github=True
        )

        # Verify mock calls
        mock_scan.assert_called_once()
        assert mock_set_output.call_count >= 8
        # Verify failure outcome
        mock_set_output.assert_any_call("outcome", "failure")

    @patch("src.__main__.get_image_scan_findings")
    def test_scan_without_github_action(self, mock_scan):
        """Test scan command without GitHub Actions output"""
        from src.__main__ import scan as scan_command

        # Mock the scan result with critical vulnerabilities
        mock_scan.return_value = ScanResult.model_validate(
            {
                "imageScanCompletedAt": datetime.now(),
                "vulnerabilitySourceUpdatedAt": datetime.now(),
                "findingSeverityCounts": {
                    "CRITICAL": 2,
                    "HIGH": 1,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFORMATIONAL": 0,
                    "UNDEFINED": 0,
                },
                "findings": [
                    {
                        "name": "CVE-2023-1234",
                        "description": "Critical vulnerability",
                        "uri": "https://example.com/CVE-2023-1234",
                        "severity": "CRITICAL",
                        "attributes": [
                            {"key": "package_name", "value": "vulnerable-package"},
                            {"key": "package_version", "value": "1.0.0"},
                        ],
                    }
                ],
            }
        )

        # Run the scan command and expect an exception
        with pytest.raises(RuntimeError):
            scan_command(
                repository="test-repo",
                tag="latest",
                fail_threshold="critical",
                github=False,  # Not a GitHub Action
            )


def test_finding_unknown_package_info():
    """Test the Finding model with missing package information"""
    # Create a Finding without package info
    finding = Finding(
        name="CVE-2023-1234",
        description="Test vulnerability",
        uri="https://example.com/CVE-2023-1234",
        severity="HIGH",
        attributes=[
            # No package_name or package_version attributes
            {"key": "other_key", "value": "other_value"}
        ],  # type: ignore
    )

    # Check that the computed fields return "Unknown"
    assert finding.package_name == "Unknown"
    assert finding.package_version == "Unknown"


def test_client_error_handling():
    """Test that ClientError is propagated except for ScanNotFoundException"""
    from unittest.mock import MagicMock

    from src.scan import get_scan_findings

    # Mock the ECR client
    mock_client = MagicMock()

    # Set up the mock to raise a ClientError with a code other than ScanNotFoundException
    error_response = {
        "Error": {"Code": "AccessDeniedException", "Message": "Access denied"}
    }
    mock_client.describe_image_scan_findings.side_effect = ClientError(
        error_response, "DescribeImageScanFindings"
    )

    # Verify the error is propagated
    with pytest.raises(ClientError) as excinfo:
        get_scan_findings(mock_client, "test-repo", "latest")

    # Verify it's the right error
    assert excinfo.value.response["Error"]["Code"] == "AccessDeniedException"
