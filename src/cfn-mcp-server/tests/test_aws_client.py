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
"""Tests for the cfn MCP Server."""

import pytest
from awslabs.cfn_mcp_server.aws_client import get_aws_client
from awslabs.cfn_mcp_server.errors import ClientError
from unittest.mock import patch, MagicMock


@pytest.mark.asyncio
class TestClient:
    """Tests on the aws_client module."""

    @patch('awslabs.cfn_mcp_server.aws_client.Session')
    @patch('awslabs.cfn_mcp_server.aws_client.environ')
    async def test_happy_path(self, mock_environ, mock_session):
        """Testing happy path."""
        client = {}
        session_instance = MagicMock()
        session_instance.client.return_value = client
        mock_session.return_value = session_instance
        mock_environ.get.return_value = 'auto'

        result = get_aws_client('cloudcontrol', 'us-east-1')

        assert result == client

    @patch('awslabs.cfn_mcp_server.aws_client.Session')
    @patch('awslabs.cfn_mcp_server.aws_client.environ')
    async def test_happy_path_no_region(self, mock_environ, mock_session):
        """Testing no region."""
        client = {}
        session_instance = MagicMock()
        session_instance.client.return_value = client
        mock_session.return_value = session_instance
        mock_environ.get.side_effect = lambda key, default=None: 'us-east-1' if key == 'AWS_REGION' else 'auto'

        result = get_aws_client('cloudcontrol')

        assert result == client

    @patch('awslabs.cfn_mcp_server.aws_client.Session')
    @patch('awslabs.cfn_mcp_server.aws_client.environ')
    async def test_env_credentials(self, mock_environ, mock_session):
        """Testing environment credentials."""
        client = {}
        session_instance = MagicMock()
        session_instance.client.return_value = client
        mock_session.return_value = session_instance
        
        # Set up environment variables
        mock_environ.get.side_effect = lambda key, default=None: {
            'AWS_CREDENTIAL_SOURCE': 'env',
            'AWS_ACCESS_KEY_ID': 'test-key',
            'AWS_SECRET_ACCESS_KEY': 'test-secret',
            'AWS_REGION': 'us-east-1'
        }.get(key, default)

        result = get_aws_client('cloudcontrol')

        assert result == client
        mock_session.assert_called_once_with(
            aws_access_key_id='test-key',
            aws_secret_access_key='test-secret',
            aws_session_token=None
        )

    @patch('awslabs.cfn_mcp_server.aws_client.Session')
    @patch('awslabs.cfn_mcp_server.aws_client.environ')
    async def test_profile_credentials(self, mock_environ, mock_session):
        """Testing profile credentials."""
        client = {}
        session_instance = MagicMock()
        session_instance.client.return_value = client
        mock_session.return_value = session_instance
        
        # Set up environment variables
        mock_environ.get.side_effect = lambda key, default=None: {
            'AWS_CREDENTIAL_SOURCE': 'profile',
            'AWS_PROFILE': 'test-profile',
            'AWS_REGION': 'us-east-1'
        }.get(key, default)

        result = get_aws_client('cloudcontrol')

        assert result == client
        mock_session.assert_called_once_with(profile_name='test-profile')

    @patch('awslabs.cfn_mcp_server.aws_client.Session')
    @patch('awslabs.cfn_mcp_server.aws_client.environ')
    async def test_instance_credentials(self, mock_environ, mock_session):
        """Testing instance credentials."""
        client = {}
        session_instance = MagicMock()
        session_instance.client.return_value = client
        mock_session.return_value = session_instance
        
        # Set up environment variables
        mock_environ.get.side_effect = lambda key, default=None: {
            'AWS_CREDENTIAL_SOURCE': 'instance',
            'AWS_REGION': 'us-east-1'
        }.get(key, default)

        result = get_aws_client('cloudcontrol')

        assert result == client
        mock_session.assert_called_once_with(aws_access_key_id=None, aws_secret_access_key=None)

    @patch('awslabs.cfn_mcp_server.aws_client.Session')
    @patch('awslabs.cfn_mcp_server.aws_client.environ')
    async def test_env_credentials_missing(self, mock_environ, mock_session):
        """Testing missing environment credentials."""
        # Set up environment variables
        mock_environ.get.side_effect = lambda key, default=None: {
            'AWS_CREDENTIAL_SOURCE': 'env',
            'AWS_REGION': 'us-east-1'
        }.get(key, default)

        with pytest.raises(ClientError, match='AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set'):
            get_aws_client('cloudcontrol')

    @patch('awslabs.cfn_mcp_server.aws_client.Session')
    @patch('awslabs.cfn_mcp_server.aws_client.environ')
    async def test_profile_missing(self, mock_environ, mock_session):
        """Testing missing profile name."""
        # Set up environment variables
        mock_environ.get.side_effect = lambda key, default=None: {
            'AWS_CREDENTIAL_SOURCE': 'profile',
            'AWS_REGION': 'us-east-1'
        }.get(key, default)

        with pytest.raises(ClientError, match='AWS_PROFILE environment variable must be set'):
            get_aws_client('cloudcontrol')

    @patch('awslabs.cfn_mcp_server.aws_client.Session')
    @patch('awslabs.cfn_mcp_server.aws_client.environ')
    async def test_expired_token(self, mock_environ, mock_session):
        """Testing token is expired."""
        session_instance = MagicMock()
        session_instance.client.side_effect = Exception('ExpiredToken')
        mock_session.return_value = session_instance
        mock_environ.get.return_value = 'us-east-1'

        with pytest.raises(ClientError, match='Your AWS credentials have expired'):
            get_aws_client('cloudcontrol')

    @patch('awslabs.cfn_mcp_server.aws_client.Session')
    @patch('awslabs.cfn_mcp_server.aws_client.environ')
    async def test_no_providers(self, mock_environ, mock_session):
        """Testing no providers given."""
        session_instance = MagicMock()
        session_instance.client.side_effect = Exception('NoCredentialProviders')
        mock_session.return_value = session_instance
        mock_environ.get.return_value = 'us-east-1'

        with pytest.raises(ClientError, match='No AWS credentials found'):
            get_aws_client('cloudcontrol')

    @patch('awslabs.cfn_mcp_server.aws_client.Session')
    @patch('awslabs.cfn_mcp_server.aws_client.environ')
    async def test_other_error(self, mock_environ, mock_session):
        """Testing error."""
        session_instance = MagicMock()
        session_instance.client.side_effect = Exception('UNRELATED')
        mock_session.return_value = session_instance
        mock_environ.get.return_value = 'us-east-1'

        with pytest.raises(ClientError, match='Error when loading client'):
            get_aws_client('cloudcontrol')