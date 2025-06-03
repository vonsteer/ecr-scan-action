from unittest.mock import MagicMock, patch

from src.__main__ import main, parse_args


class TestMain:
    """Tests for the main entry point functionality"""

    @patch(
        "sys.argv",
        ["ecr-scan", "test-repo", "latest", "--github_action", "--region", "us-west-2"],
    )
    def test_parse_args(self) -> None:
        """Test argument parsing"""
        args = parse_args()
        assert args.repository == "test-repo"
        assert args.tag == "latest"
        assert args.github_action is True
        assert args.region == "us-west-2"
        assert args.fail_threshold == "high"  # default value
        assert args.ignore_list is None
        assert args.max_retries == 10  # default value
        assert args.retry_delay == 5  # default value

    @patch("src.__main__.scan")
    @patch("src.__main__.parse_args")
    def test_main_function(
        self,
        mock_parse_args: MagicMock,
        mock_scan: MagicMock,
    ) -> None:
        """Test the main function that calls scan with parsed arguments"""
        # Mock the parsed arguments
        mock_args = MagicMock()
        mock_args.repository = "test-repo"
        mock_args.tag = "latest"
        mock_args.fail_threshold = "high"
        mock_args.ignore_list = None
        mock_args.github_action = True
        mock_args.region = "us-east-2"
        mock_args.max_retries = 10
        mock_args.retry_delay = 5
        mock_parse_args.return_value = mock_args

        # Execute the main function
        main()

        # Verify scan was called with the correct arguments
        mock_scan.assert_called_once_with(
            repository="test-repo",
            tag="latest",
            fail_threshold="high",
            ignore_list=None,
            github=True,
            region="us-east-2",
            max_retries=10,
            retry_delay=5,
        )
