HEADER = """
### 🛡️ AWS ECR Security Scan Results
#### 📦 Image: `{repository}:{tag}`
"""

FAILURE_FOOTER = """
⚠️ **Build Failed**: Vulnerabilities were detected that exceeded threshold.
These must be addressed before merging.
"""
NEUTRAL_FOOTER = """
🔍 **Build Neutral**: Vulnerabilities were detected but did not exceed the threshold.
Please review these security findings before merging.
"""
SUCCESS_FOOTER = """
🎉 **Build Succeeded**: No vulnerabilities were detected.
"""

IGNORED_SECTION = """
#### 🚨 Ignored Findings
{ignored_findings}
"""
IGNORED_NOT_FOUND = """

⚠️ **Warning**: Some ignored CVEs were not found in the scan results.
"""

SUMMARY_SECTION = """
#### 📈 Vulnerability Summary ({total})
{summary}
"""
DETAILED_FINDINGS_SECTION = """
#### 🔍 Detailed Findings
{detailed_findings}
"""

LEVEL_EMOJI_MAPPING = {
    "CRITICAL": "⚠️",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFORMATIONAL": "🔵",
    "UNDEFINED": "❓",
}

SEVERITY_LEVELS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
    "undefined": 0,
    "none": 5,
}

CRITICAL_MKD = "⚠️ CRITICAL: {0}"
HIGH_MKD = "🔴 HIGH: {0}"
MEDIUM_MKD = "🟡 MEDIUM: {0}"
LOW_MKD = "🟢 LOW: {0}"
INFORMATIONAL_MKD = "🔵 INFORMATIONAL: {0}"
UNDEFINED_MKD = "❓ UNDEFINED: {0}"

MAX_DESCRIPTION_LENGTH = 300
