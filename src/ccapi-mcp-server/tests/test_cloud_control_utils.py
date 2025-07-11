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
from awslabs.ccapi_mcp_server.cloud_control_utils import (
    add_default_tags,
    progress_event,
    validate_patch,
)
from awslabs.ccapi_mcp_server.errors import ClientError


@pytest.mark.asyncio
class TestUtils:
    """Tests on the cloud_control_utils module."""

    async def test_empty_patch(self):
        """Testing no information in patch."""
        validate_patch([])

    async def test_patch_with_invalid_shape_1(self):
        """Testing bad shape."""
        with pytest.raises(ClientError):
            validate_patch(['not_a_dict'])

    async def test_patch_with_invalid_shape_2(self):
        """Testing no operation."""
        with pytest.raises(ClientError):
            validate_patch([{'not-op': 'is bad'}])

    async def test_patch_with_invalid_shape_3(self):
        """Testing invalid operation."""
        with pytest.raises(ClientError):
            validate_patch([{'op': 'invalid'}])

    async def test_patch_with_invalid_shape_4(self):
        """Testing no path."""
        with pytest.raises(ClientError):
            validate_patch([{'op': 'add', 'not-path': 'is bad'}])

    async def test_happy_remove(self):
        """Testing simple remove."""
        validate_patch([{'op': 'remove', 'path': '/property'}])

    async def test_patch_with_invalid_shape_5(self):
        """Testing no value."""
        with pytest.raises(ClientError):
            validate_patch([{'op': 'add', 'path': '/property', 'not-value': 'is bad'}])

    async def test_happy_add(self):
        """Testing simple add."""
        validate_patch([{'op': 'add', 'path': '/property', 'value': '25'}])

    async def test_patch_with_invalid_shape_6(self):
        """Testing no from."""
        with pytest.raises(ClientError):
            validate_patch([{'op': 'move', 'path': '/property', 'not-from': 'is bad'}])

    async def test_progress_event(self):
        """Testing mapping progress event."""
        request = {
            'OperationStatus': 'SUCCESS',
            'TypeName': 'AWS::CodeStarConnections::Connection',
            'RequestToken': '25',
        }

        response = {
            'status': 'SUCCESS',
            'resource_type': 'AWS::CodeStarConnections::Connection',
            'is_complete': True,
            'request_token': '25',
        }

        assert progress_event(request, None) == response

    async def test_progress_event_full(self):
        """Testing mapping progress event with all props."""
        request = {
            'OperationStatus': 'SUCCESS',
            'TypeName': 'AWS::CodeStarConnections::Connection',
            'RequestToken': '25',
            'Identifier': 'id',
            'StatusMessage': 'good job',
            'ResourceModel': 'model',
            'ErrorCode': 'NONE',
            'EventTime': '25',
            'RetryAfter': '10',
        }

        response = {
            'status': 'SUCCESS',
            'resource_type': 'AWS::CodeStarConnections::Connection',
            'is_complete': True,
            'request_token': '25',
            'identifier': 'id',
            'status_message': 'good job',
            'resource_info': 'model',
            'error_code': 'NONE',
            'event_time': '25',
            'retry_after': '10',
        }

        assert progress_event(request, None) == response

    async def test_progress_event_failed(self):
        """Testing mapping progress event with all props."""
        request = {
            'OperationStatus': 'FAILED',
            'TypeName': 'AWS::CodeStarConnections::Connection',
            'RequestToken': '25',
            'Identifier': 'id',
            'StatusMessage': 'good job',
            'ResourceModel': 'model',
            'ErrorCode': 'NONE',
            'EventTime': '25',
            'RetryAfter': '10',
        }

        response = {
            'status': 'FAILED',
            'resource_type': 'AWS::CodeStarConnections::Connection',
            'is_complete': True,
            'request_token': '25',
            'identifier': 'id',
            'status_message': 'good job',
            'resource_info': 'model',
            'error_code': 'NONE',
            'event_time': '25',
            'retry_after': '10',
        }

        assert progress_event(request, None) == response

    async def test_progress_event_empty_list_chooses_status_message(self):
        """Testing mapping progress event."""
        request = {
            'OperationStatus': 'SUCCESS',
            'TypeName': 'AWS::CodeStarConnections::Connection',
            'RequestToken': '25',
            'StatusMessage': 'good job',
        }

        response = {
            'status': 'SUCCESS',
            'resource_type': 'AWS::CodeStarConnections::Connection',
            'is_complete': True,
            'request_token': '25',
            'status_message': 'good job',
        }

        assert progress_event(request, []) == response

    async def test_progress_event_successful_hook_chooses_status_message(self):
        """Testing mapping progress event."""
        request = {
            'OperationStatus': 'SUCCESS',
            'TypeName': 'AWS::CodeStarConnections::Connection',
            'RequestToken': '25',
            'StatusMessage': 'good job',
        }

        hook = {'HookStatus': 'HOOK_COMPLETE_SUCCEEDED', 'HookStatusMessage': 'DONT SEE THIS'}

        response = {
            'status': 'SUCCESS',
            'resource_type': 'AWS::CodeStarConnections::Connection',
            'is_complete': True,
            'request_token': '25',
            'status_message': 'good job',
        }

        assert progress_event(request, [hook]) == response

    async def test_progress_event_failed_hook_chooses_hook_message(self):
        """Testing mapping progress event."""
        request = {
            'OperationStatus': 'SUCCESS',
            'TypeName': 'AWS::CodeStarConnections::Connection',
            'RequestToken': '25',
            'StatusMessage': 'good job',
        }

        hook = {'HookStatus': 'HOOK_FAILED', 'HookStatusMessage': 'HOOK FAILED!!'}

        response = {
            'status': 'SUCCESS',
            'resource_type': 'AWS::CodeStarConnections::Connection',
            'is_complete': True,
            'request_token': '25',
            'status_message': 'HOOK FAILED!!',
        }

        assert progress_event(request, [hook]) == response

    async def test_add_default_tags_empty_properties(self):
        """Test add_default_tags with empty properties."""
        import os

        os.environ['DEFAULT_TAGGING'] = 'true'
        properties = {}
        schema = {'properties': {'Tags': {}}}
        result = add_default_tags(properties, schema)
        assert result == {}
        del os.environ['DEFAULT_TAGGING']

    async def test_add_default_tags_no_tag_support(self):
        """Test add_default_tags with resource that doesn't support tags."""
        import os

        os.environ['DEFAULT_TAGGING'] = 'true'
        properties = {'Name': 'test-resource'}
        schema = {'properties': {}}
        result = add_default_tags(properties, schema)
        assert result == {'Name': 'test-resource'}
        assert 'Tags' not in result
        del os.environ['DEFAULT_TAGGING']

    async def test_add_default_tags_with_existing_tags(self):
        """Test add_default_tags with existing tags."""
        import os

        os.environ['DEFAULT_TAGGING'] = 'true'
        properties = {'Name': 'test-resource', 'Tags': [{'Key': 'MANAGED_BY', 'Value': 'CUSTOM'}]}
        schema = {'properties': {'Tags': {}}}
        result = add_default_tags(properties, schema)

        assert result['Name'] == 'test-resource'
        assert len(result['Tags']) == 2
        assert {'Key': 'MANAGED_BY', 'Value': 'CUSTOM'} in result['Tags']
        assert {
            'Key': 'MCP_SERVER_SOURCE_CODE',
            'Value': 'https://github.com/awslabs/mcp/tree/main/src/ccapi-mcp-server',
        } in result['Tags']
        del os.environ['DEFAULT_TAGGING']

    async def test_add_default_tags_no_existing_tags(self):
        """Test add_default_tags with no existing tags."""
        import os

        os.environ['DEFAULT_TAGGING'] = 'true'
        properties = {'Name': 'test-resource'}
        schema = {'properties': {'Tags': {}}}
        result = add_default_tags(properties, schema)

        assert result['Name'] == 'test-resource'
        assert len(result['Tags']) == 2
        assert {'Key': 'MANAGED_BY', 'Value': 'CCAPI-MCP-SERVER'} in result['Tags']
        assert {
            'Key': 'MCP_SERVER_SOURCE_CODE',
            'Value': 'https://github.com/awslabs/mcp/tree/main/src/ccapi-mcp-server',
        } in result['Tags']
        del os.environ['DEFAULT_TAGGING']

    async def test_add_default_tags_with_all_existing_tags(self):
        """Test add_default_tags with all default tags already present."""
        import os

        os.environ['DEFAULT_TAGGING'] = 'true'
        properties = {
            'Name': 'test-resource',
            'Tags': [
                {'Key': 'MANAGED_BY', 'Value': 'CUSTOM'},
                {'Key': 'MCP_SERVER_SOURCE_CODE', 'Value': 'CUSTOM'},
            ],
        }
        schema = {'properties': {'Tags': {}}}
        result = add_default_tags(properties, schema)

        assert result['Name'] == 'test-resource'
        assert len(result['Tags']) == 2
        assert {'Key': 'MANAGED_BY', 'Value': 'CUSTOM'} in result['Tags']
        assert {'Key': 'MCP_SERVER_SOURCE_CODE', 'Value': 'CUSTOM'} in result['Tags']
        del os.environ['DEFAULT_TAGGING']

    async def test_add_default_tags_disabled(self):
        """Test add_default_tags when DEFAULT_TAGGING is disabled."""
        import os

        os.environ.pop('DEFAULT_TAGGING', None)  # Ensure it's not set
        properties = {'Name': 'test-resource'}
        schema = {'properties': {'Tags': {}}}
        result = add_default_tags(properties, schema)

        assert result == {'Name': 'test-resource'}
        assert 'Tags' not in result
