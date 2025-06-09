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

import os
import pytest
from awslabs.cfn_mcp_server.cloud_control_utils import (
    add_default_tags,
    progress_event,
    validate_patch,
)
from awslabs.cfn_mcp_server.errors import ClientError
from unittest import mock


def test_validate_patch_valid():
    """Test that validate_patch accepts valid patch documents."""
    patch_document = [
        {'op': 'add', 'path': '/Tags', 'value': [{'Key': 'Name', 'Value': 'test'}]},
        {'op': 'replace', 'path': '/VersioningConfiguration/Status', 'value': 'Enabled'},
        {'op': 'remove', 'path': '/WebsiteConfiguration'},
        {'op': 'move', 'path': '/NewPath', 'from': '/OldPath'},
        {'op': 'copy', 'path': '/NewPath', 'from': '/OldPath'},
        {'op': 'test', 'path': '/Tags', 'value': [{'Key': 'Name', 'Value': 'test'}]},
    ]
    # Should not raise an exception
    validate_patch(patch_document)


def test_validate_patch_invalid_not_dict():
    """Test that validate_patch rejects patch documents with non-dictionary items."""
    patch_document = ['not a dict']
    with pytest.raises(ClientError, match='Each patch operation must be a dictionary'):
        validate_patch(patch_document)


def test_validate_patch_invalid_no_op():
    """Test that validate_patch rejects patch operations without an 'op' field."""
    patch_document = [{'path': '/Tags'}]
    with pytest.raises(ClientError, match="Each patch operation must include an 'op' field"):
        validate_patch(patch_document)


def test_validate_patch_invalid_op():
    """Test that validate_patch rejects patch operations with invalid 'op' values."""
    patch_document = [{'op': 'invalid', 'path': '/Tags'}]
    with pytest.raises(ClientError, match="Operation 'invalid' is not supported"):
        validate_patch(patch_document)


def test_validate_patch_invalid_no_path():
    """Test that validate_patch rejects patch operations without a 'path' field."""
    patch_document = [{'op': 'add'}]
    with pytest.raises(ClientError, match="Each patch operation must include a 'path' field"):
        validate_patch(patch_document)


def test_validate_patch_invalid_no_value():
    """Test that validate_patch rejects 'add' operations without a 'value' field."""
    patch_document = [{'op': 'add', 'path': '/Tags'}]
    with pytest.raises(ClientError, match="The 'add' operation requires a 'value' field"):
        validate_patch(patch_document)


def test_validate_patch_invalid_no_from():
    """Test that validate_patch rejects 'move' operations without a 'from' field."""
    patch_document = [{'op': 'move', 'path': '/Tags'}]
    with pytest.raises(ClientError, match="The 'move' operation requires a 'from' field"):
        validate_patch(patch_document)


def test_progress_event_basic():
    """Test that progress_event correctly maps basic CloudControl API response fields."""
    response_event = {
        'OperationStatus': 'SUCCESS',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
    }
    result = progress_event(response_event, None)
    assert result['status'] == 'SUCCESS'
    assert result['resource_type'] == 'AWS::S3::Bucket'
    assert result['is_complete'] is True
    assert result['request_token'] == 'token123'


def test_progress_event_with_identifier():
    """Test that progress_event correctly includes the identifier field when present."""
    response_event = {
        'OperationStatus': 'SUCCESS',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'Identifier': 'my-bucket',
    }
    result = progress_event(response_event, None)
    assert result['identifier'] == 'my-bucket'


def test_progress_event_with_resource_model():
    """Test that progress_event correctly maps ResourceModel to resource_info."""
    response_event = {
        'OperationStatus': 'SUCCESS',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'ResourceModel': '{"BucketName": "my-bucket"}',
    }
    result = progress_event(response_event, None)
    assert result['resource_info'] == '{"BucketName": "my-bucket"}'


def test_progress_event_with_error_code():
    """Test that progress_event correctly includes error_code when present."""
    response_event = {
        'OperationStatus': 'FAILED',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'ErrorCode': 'NotFound',
    }
    result = progress_event(response_event, None)
    assert result['error_code'] == 'NotFound'


def test_progress_event_with_event_time():
    """Test that progress_event correctly includes event_time when present."""
    response_event = {
        'OperationStatus': 'SUCCESS',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'EventTime': '2023-01-01T00:00:00Z',
    }
    result = progress_event(response_event, None)
    assert result['event_time'] == '2023-01-01T00:00:00Z'


def test_progress_event_with_retry_after():
    """Test that progress_event correctly includes retry_after when present."""
    response_event = {
        'OperationStatus': 'PENDING',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'RetryAfter': 5,
    }
    result = progress_event(response_event, None)
    assert result['retry_after'] == 5


def test_progress_event_with_status_message():
    """Test that progress_event correctly includes status_message when present."""
    response_event = {
        'OperationStatus': 'FAILED',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'StatusMessage': 'Resource creation failed',
    }
    result = progress_event(response_event, None)
    assert result['status_message'] == 'Resource creation failed'


def test_progress_event_with_hooks_message():
    """Test that progress_event prioritizes hook status messages over CloudControl status messages."""
    response_event = {
        'OperationStatus': 'FAILED',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'StatusMessage': 'Resource creation failed',
    }
    hooks_events = [
        {
            'HookStatus': 'HOOK_COMPLETE_FAILED',
            'HookStatusMessage': 'Hook validation failed',
        }
    ]
    result = progress_event(response_event, hooks_events)
    assert result['status_message'] == 'Hook validation failed'


def test_add_default_tags_enabled_list_tags():
    """Test that add_default_tags adds default tags when enabled with list-style tags."""
    # Test with DEFAULT_TAGS=enabled and Tags as a list
    with mock.patch.dict(os.environ, {'DEFAULT_TAGS': 'enabled'}):
        resource_properties = {
            'BucketName': 'test-bucket',
            'Tags': [{'Key': 'ExistingTag', 'Value': 'ExistingValue'}],
        }

        result = add_default_tags(resource_properties)

        # Check that original properties are not modified
        assert resource_properties != result

        # Check that default tags were added
        assert len(result['Tags']) == 3

        # Convert tags to dict for easier checking
        tags_dict = {tag['Key']: tag['Value'] for tag in result['Tags']}

        # Check that original tag is preserved
        assert tags_dict['ExistingTag'] == 'ExistingValue'

        # Check that default tags are added
        assert tags_dict['MANAGED_BY'] == 'CloudFormation MCP Server'
        assert (
            tags_dict['MCP_SERVER_SOURCE_CODE']
            == 'https://github.com/awslabs/mcp/tree/main/src/cfn-mcp-server'
        )


def test_add_default_tags_default_behavior():
    """Test that add_default_tags defaults to enabled when DEFAULT_TAGS is not set."""
    # Test with DEFAULT_TAGS not set - should default to enabled
    with mock.patch.dict(os.environ, {}, clear=True):
        resource_properties = {
            'BucketName': 'test-bucket',
            'Tags': [{'Key': 'ExistingTag', 'Value': 'ExistingValue'}],
        }

        result = add_default_tags(resource_properties)

        # Check that default tags were added
        assert len(result['Tags']) == 3

        # Convert tags to dict for easier checking
        tags_dict = {tag['Key']: tag['Value'] for tag in result['Tags']}

        # Check that default tags are added
        assert tags_dict['MANAGED_BY'] == 'CloudFormation MCP Server'
        assert (
            tags_dict['MCP_SERVER_SOURCE_CODE']
            == 'https://github.com/awslabs/mcp/tree/main/src/cfn-mcp-server'
        )


def test_add_default_tags_enabled_dict_tags():
    """Test that add_default_tags adds default tags when enabled with dictionary-style tags."""
    # Test with DEFAULT_TAGS=enabled and Tags as a dictionary
    with mock.patch.dict(os.environ, {'DEFAULT_TAGS': 'enabled'}):
        resource_properties = {
            'BucketName': 'test-bucket',
            'Tags': {'ExistingTag': 'ExistingValue'},
        }

        result = add_default_tags(resource_properties)

        # Check that original properties are not modified
        assert resource_properties != result

        # Check that default tags were added
        assert len(result['Tags']) == 3

        # Check that original tag is preserved
        assert result['Tags']['ExistingTag'] == 'ExistingValue'

        # Check that default tags are added
        assert result['Tags']['MANAGED_BY'] == 'CloudFormation MCP Server'
        assert (
            result['Tags']['MCP_SERVER_SOURCE_CODE']
            == 'https://github.com/awslabs/mcp/tree/main/src/cfn-mcp-server'
        )


def test_add_default_tags_enabled_no_tags():
    """Test that add_default_tags returns original properties when resource doesn't support tagging."""
    # Test with DEFAULT_TAGS=enabled but no Tags property
    with mock.patch.dict(os.environ, {'DEFAULT_TAGS': 'enabled'}):
        resource_properties = {'BucketName': 'test-bucket'}

        result = add_default_tags(resource_properties)

        # Should return the original properties since there's no Tags property
        assert result == resource_properties


def test_add_default_tags_disabled():
    """Test that add_default_tags doesn't add tags when DEFAULT_TAGS is disabled."""
    # Test with DEFAULT_TAGS=disabled
    with mock.patch.dict(os.environ, {'DEFAULT_TAGS': 'disabled'}):
        resource_properties = {
            'BucketName': 'test-bucket',
            'Tags': [{'Key': 'ExistingTag', 'Value': 'ExistingValue'}],
        }

        result = add_default_tags(resource_properties)

        # Should return the original properties
        assert result == resource_properties


def test_add_default_tags_explicitly_disabled():
    """Test that add_default_tags respects explicit DEFAULT_TAGS=disabled setting."""
    # Test with DEFAULT_TAGS explicitly set to disabled
    with mock.patch.dict(os.environ, {'DEFAULT_TAGS': 'disabled'}):
        resource_properties = {
            'BucketName': 'test-bucket',
            'Tags': [{'Key': 'ExistingTag', 'Value': 'ExistingValue'}],
        }

        result = add_default_tags(resource_properties)

        # Should return the original properties
        assert result == resource_properties
