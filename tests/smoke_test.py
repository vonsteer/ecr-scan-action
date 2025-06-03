#!/usr/bin/env python
"""
Smoke test to verify that the package can be imported and executed.
This file is used during the CI process to validate that the built package is working.
"""

import subprocess
import sys


def test_smoke() -> None:
    try:
        # Import the main module to verify it can be imported
        import src.__main__

        print("Successfully imported src.__main__")

        # Try to run the CLI with --help
        result = subprocess.run(
            [sys.executable, "-m", "src.__main__", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )

        # Verify the help message contains expected content
        assert "Scan ECR images for vulnerabilities" in result.stdout
        assert "--fail-threshold" in result.stdout
        assert "--ignore-list" in result.stdout

        print("CLI help command executed successfully")
    except (ImportError, subprocess.CalledProcessError, AssertionError) as e:
        print(f"Smoke test failed: {e}")
        raise SystemExit(1) from e


if __name__ == "__main__":
    test_smoke()
