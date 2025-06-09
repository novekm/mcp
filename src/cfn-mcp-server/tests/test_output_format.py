# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for the output formatting in the cfn MCP Server."""

from awslabs.cfn_mcp_server.server import get_output_format_instructions
from unittest.mock import patch


class TestOutputFormat:
    """Test output formatting functionality."""

    @patch('awslabs.cfn_mcp_server.server.environ')
    def test_dynamic_format(self, mock_environ):
        """Test dynamic output format."""
        # Setup mock
        mock_environ.get.return_value = 'dynamic'

        # Call the function
        result = get_output_format_instructions()

        # Verify result contains dynamic format instructions
        assert 'Dynamically choose the most appropriate format' in result
        assert 'CloudFormation templates' in result
        assert 'JSON data' in result
        assert 'Terraform resources' in result

    @patch('awslabs.cfn_mcp_server.server.environ')
    def test_emoji_format(self, mock_environ):
        """Test emoji output format."""
        # Setup mock
        mock_environ.get.return_value = 'emoji'

        # Call the function
        result = get_output_format_instructions()

        # Verify result contains emoji format instructions
        assert 'emoji-rich formatting' in result
        assert '🔑 for keys' in result
        assert '🪣 for S3 buckets' in result
        assert '💾 for databases' in result
        assert '🖥️ for compute resources' in result

    @patch('awslabs.cfn_mcp_server.server.environ')
    def test_json_format(self, mock_environ):
        """Test JSON output format."""
        # Setup mock
        mock_environ.get.return_value = 'json'

        # Call the function
        result = get_output_format_instructions()

        # Verify result contains JSON format instructions
        assert 'JSON formatting' in result
        assert 'proper indentation' in result
        assert 'keys are quoted' in result

    @patch('awslabs.cfn_mcp_server.server.environ')
    def test_yaml_format(self, mock_environ):
        """Test YAML output format."""
        # Setup mock
        mock_environ.get.return_value = 'yaml'

        # Call the function
        result = get_output_format_instructions()

        # Verify result contains YAML format instructions
        assert 'YAML formatting' in result
        assert 'dashes for arrays' in result
        assert 'multiline strings' in result

    @patch('awslabs.cfn_mcp_server.server.environ')
    def test_default_format(self, mock_environ):
        """Test default output format when not specified."""
        # Setup mock to return None
        mock_environ.get.return_value = None

        # Call the function
        result = get_output_format_instructions()

        # Verify result defaults to dynamic format
        assert 'Dynamically choose the most appropriate format' in result
