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
from unittest import mock
from awslabs.cfn_mcp_server.cloud_control_utils import validate_patch, progress_event, add_default_tags
from awslabs.cfn_mcp_server.errors import ClientError


def test_validate_patch_valid():
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
    patch_document = ['not a dict']
    with pytest.raises(ClientError, match='Each patch operation must be a dictionary'):
        validate_patch(patch_document)


def test_validate_patch_invalid_no_op():
    patch_document = [{'path': '/Tags'}]
    with pytest.raises(ClientError, match="Each patch operation must include an 'op' field"):
        validate_patch(patch_document)


def test_validate_patch_invalid_op():
    patch_document = [{'op': 'invalid', 'path': '/Tags'}]
    with pytest.raises(ClientError, match="Operation 'invalid' is not supported"):
        validate_patch(patch_document)


def test_validate_patch_invalid_no_path():
    patch_document = [{'op': 'add'}]
    with pytest.raises(ClientError, match="Each patch operation must include a 'path' field"):
        validate_patch(patch_document)


def test_validate_patch_invalid_no_value():
    patch_document = [{'op': 'add', 'path': '/Tags'}]
    with pytest.raises(ClientError, match="The 'add' operation requires a 'value' field"):
        validate_patch(patch_document)


def test_validate_patch_invalid_no_from():
    patch_document = [{'op': 'move', 'path': '/Tags'}]
    with pytest.raises(ClientError, match="The 'move' operation requires a 'from' field"):
        validate_patch(patch_document)


def test_progress_event_basic():
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
    response_event = {
        'OperationStatus': 'SUCCESS',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'Identifier': 'my-bucket',
    }
    result = progress_event(response_event, None)
    assert result['identifier'] == 'my-bucket'


def test_progress_event_with_resource_model():
    response_event = {
        'OperationStatus': 'SUCCESS',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'ResourceModel': '{"BucketName": "my-bucket"}',
    }
    result = progress_event(response_event, None)
    assert result['resource_info'] == '{"BucketName": "my-bucket"}'


def test_progress_event_with_error_code():
    response_event = {
        'OperationStatus': 'FAILED',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'ErrorCode': 'NotFound',
    }
    result = progress_event(response_event, None)
    assert result['error_code'] == 'NotFound'


def test_progress_event_with_event_time():
    response_event = {
        'OperationStatus': 'SUCCESS',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'EventTime': '2023-01-01T00:00:00Z',
    }
    result = progress_event(response_event, None)
    assert result['event_time'] == '2023-01-01T00:00:00Z'


def test_progress_event_with_retry_after():
    response_event = {
        'OperationStatus': 'PENDING',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'RetryAfter': 5,
    }
    result = progress_event(response_event, None)
    assert result['retry_after'] == 5


def test_progress_event_with_status_message():
    response_event = {
        'OperationStatus': 'FAILED',
        'TypeName': 'AWS::S3::Bucket',
        'RequestToken': 'token123',
        'StatusMessage': 'Resource creation failed',
    }
    result = progress_event(response_event, None)
    assert result['status_message'] == 'Resource creation failed'


def test_progress_event_with_hooks_message():
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
    # Test with DEFAULT_TAGS=enabled and Tags as a list
    with mock.patch.dict(os.environ, {'DEFAULT_TAGS': 'enabled'}):
        resource_properties = {
            'BucketName': 'test-bucket',
            'Tags': [
                {'Key': 'ExistingTag', 'Value': 'ExistingValue'}
            ]
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
        assert tags_dict['MCP_SERVER_SOURCE_CODE'] == 'https://github.com/awslabs/mcp/tree/main/src/cfn-mcp-server'
        
def test_add_default_tags_default_behavior():
    # Test with DEFAULT_TAGS not set - should default to enabled
    with mock.patch.dict(os.environ, {}, clear=True):
        resource_properties = {
            'BucketName': 'test-bucket',
            'Tags': [
                {'Key': 'ExistingTag', 'Value': 'ExistingValue'}
            ]
        }
        
        result = add_default_tags(resource_properties)
        
        # Check that default tags were added
        assert len(result['Tags']) == 3
        
        # Convert tags to dict for easier checking
        tags_dict = {tag['Key']: tag['Value'] for tag in result['Tags']}
        
        # Check that default tags are added
        assert tags_dict['MANAGED_BY'] == 'CloudFormation MCP Server'
        assert tags_dict['MCP_SERVER_SOURCE_CODE'] == 'https://github.com/awslabs/mcp/tree/main/src/cfn-mcp-server'


def test_add_default_tags_enabled_dict_tags():
    # Test with DEFAULT_TAGS=enabled and Tags as a dictionary
    with mock.patch.dict(os.environ, {'DEFAULT_TAGS': 'enabled'}):
        resource_properties = {
            'BucketName': 'test-bucket',
            'Tags': {
                'ExistingTag': 'ExistingValue'
            }
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
        assert result['Tags']['MCP_SERVER_SOURCE_CODE'] == 'https://github.com/awslabs/mcp/tree/main/src/cfn-mcp-server'


def test_add_default_tags_enabled_no_tags():
    # Test with DEFAULT_TAGS=enabled but no Tags property
    with mock.patch.dict(os.environ, {'DEFAULT_TAGS': 'enabled'}):
        resource_properties = {
            'BucketName': 'test-bucket'
        }
        
        result = add_default_tags(resource_properties)
        
        # Should return the original properties since there's no Tags property
        assert result == resource_properties


def test_add_default_tags_disabled():
    # Test with DEFAULT_TAGS=disabled
    with mock.patch.dict(os.environ, {'DEFAULT_TAGS': 'disabled'}):
        resource_properties = {
            'BucketName': 'test-bucket',
            'Tags': [
                {'Key': 'ExistingTag', 'Value': 'ExistingValue'}
            ]
        }
        
        result = add_default_tags(resource_properties)
        
        # Should return the original properties
        assert result == resource_properties


def test_add_default_tags_explicitly_disabled():
    # Test with DEFAULT_TAGS explicitly set to disabled
    with mock.patch.dict(os.environ, {'DEFAULT_TAGS': 'disabled'}):
        resource_properties = {
            'BucketName': 'test-bucket',
            'Tags': [
                {'Key': 'ExistingTag', 'Value': 'ExistingValue'}
            ]
        }
        
        result = add_default_tags(resource_properties)
        
        # Should return the original properties
        assert result == resource_properties