import os
import tempfile
from unittest.mock import patch

from src.__main__ import set_output


class TestSetOutput:
    """Tests for the GitHub Actions output functionality"""

    def test_set_output_single_line(self) -> None:
        """Test setting a single line output variable"""
        with (
            tempfile.NamedTemporaryFile(mode="w+") as temp,
            patch.dict(os.environ, {"GITHUB_OUTPUT": temp.name}),
        ):
            # Set a simple output variable
            set_output("test_name", "test_value")

            # Read the output file
            temp.seek(0)
            content = temp.read()

            # Verify the output
            assert content == "test_name=test_value\n"

    def test_set_output_multiline(self) -> None:
        """Test setting a multiline output variable"""
        multiline_value = """line1
line2
line3"""

        with (
            tempfile.NamedTemporaryFile(mode="w+") as temp,
            patch.dict(os.environ, {"GITHUB_OUTPUT": temp.name}),
        ):
            # Set a multiline output variable
            set_output("test_name", multiline_value)

            # Read the output file
            temp.seek(0)
            content = temp.read()

            # Verify the output uses the delimiter syntax
            assert "test_name<<" in content
            assert "line1\nline2\nline3\n" in content
