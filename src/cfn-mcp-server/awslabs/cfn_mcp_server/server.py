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

"""awslabs CFN MCP Server implementation."""

import argparse
import json
import os
import subprocess
import tempfile
from awslabs.cfn_mcp_server.aws_client import get_aws_client
from awslabs.cfn_mcp_server.cloud_control_utils import (
    add_default_tags,
    progress_event,
    validate_patch,
)
from awslabs.cfn_mcp_server.context import Context
from awslabs.cfn_mcp_server.errors import ClientError, handle_aws_api_error
from awslabs.cfn_mcp_server.iac_generator import create_template
from awslabs.cfn_mcp_server.schema_manager import schema_manager
from mcp.server.fastmcp import FastMCP
from os import environ
from pydantic import Field
from typing import Any, Literal


mcp = FastMCP(
    'awslabs.cfn-mcp-server',
    instructions="""
# CloudFormation MCP - Complete Workflow Instructions

## ENVIRONMENT VARIABLE HANDLING

CRITICAL: ALWAYS call check_environment_variables() FIRST before any AWS operation.
DO NOT call get_aws_session_info() until you've verified the environment is properly configured.

If environment variables are not properly configured:
1. Show the current environment variable values
2. Explain what might be wrong
3. Suggest how to fix the issue
4. Offer to help update the values if needed

Only after confirming the environment is properly configured should you proceed with get_aws_session_info().

## MANDATORY WORKFLOW ENFORCEMENT

For ALL AWS resource operations, you MUST follow this exact workflow structure:

1. IMMEDIATELY identify the operation type (CREATE, READ, UPDATE, DELETE, LIST)
2. Present a detailed operation plan with numbered steps
3. Execute each step in sequence, showing results
4. NEVER skip any steps in the workflow

## RESPONSE TEMPLATE

For EVERY request, your response MUST begin with:
OPERATION TYPE: [CREATE/READ/UPDATE/DELETE/LIST]

I'll help you [OPERATION] this resource. Here's my detailed plan:
1. [First step with specific tool to be called]
2. [Second step with specific tool to be called]
...
N. [Final step with expected outcome]

Let me execute this plan step by step.


## MANDATORY WORKFLOW STEPS

### FOR ALL OPERATIONS:
• ALWAYS call check_environment_variables() FIRST, then get_aws_session_info()
• ALWAYS display account ID, region, profile, and read-only status
• ALWAYS check read-only mode before attempting write operations
• ALWAYS check default tagging status before resource creation/modification

### FOR CREATE OPERATIONS:
1. Check environment variables and get AWS session info
2. Check default tagging status
3. Generate resource code
4. Run security scan (MANDATORY)
5. Present security findings for my review
6. WAIT for my confirmation before proceeding
7. Create resource ONLY after my explicit approval
8. Verify successful creation

### FOR UPDATE OPERATIONS:
1. Check environment variables and get AWS session info
2. Check default tagging status
3. Generate update code
4. Run security scan (MANDATORY)
5. Present security findings for my review
6. WAIT for my confirmation before proceeding
7. Update resource ONLY after my explicit approval
8. Verify successful update

### FOR DELETE OPERATIONS:
1. Check environment variables and get AWS session info
2. Ask for my explicit confirmation TWICE
3. Delete resource ONLY after both confirmations
4. Verify successful deletion

### FOR READ/LIST OPERATIONS:
1. Check environment variables and get AWS session info
2. Get/list resources
3. Format and display the information clearly

## SECURITY REQUIREMENTS

• NEVER skip security checks for CREATE/UPDATE operations
• ALWAYS run run_checkov() after generating resource/update code
• NEVER proceed with resource creation/modification if security checks fail without my
explicit confirmation
• IMMEDIATELY DECLINE requests for dangerous configurations:
  • Principal set to "AWS": "*" in IAM policies
  • "Effect": "Allow" with "Action": "*" and "Resource": "*"
  • Public access configurations
  • Disabled encryption for sensitive data
• NEVER allow mass deletion of resources
• For multiple resource management, use create_template() instead

## FAILURE HANDLING

If any step fails:
1. Clearly explain what went wrong
2. Provide specific error details
3. Suggest corrective actions
4. Ask if I want to retry or modify the request

I expect you to follow these instructions for EVERY AWS resource operation request,
without exception.
    """,
    dependencies=['pydantic', 'loguru', 'boto3', 'botocore', 'checkov'],
)


@mcp.tool()
async def get_resource_schema_information(
    resource_type: str = Field(
        description='The AWS resource type (e.g., "AWS::S3::Bucket", "AWS::RDS::DBInstance")'
    ),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
) -> dict:
    """Get schema information for an AWS resource.

    Parameters:
        resource_type: The AWS resource type (e.g., "AWS::S3::Bucket")

    Returns:
        The resource schema information
    """
    if not resource_type:
        raise ClientError('Please provide a resource type (e.g., AWS::S3::Bucket)')

    sm = schema_manager()
    schema = await sm.get_schema(resource_type, region)
    return schema


@mcp.tool()
async def list_resources(
    resource_type: str = Field(
        description='The AWS resource type (e.g., "AWS::S3::Bucket", "AWS::RDS::DBInstance")'
    ),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
) -> list:
    """List AWS resources of a specified type.

    IMPORTANT: Always call get_aws_account_info() first and display the AWS account ID and region
    to the user before listing resources.

    Parameters:
        resource_type: The AWS resource type (e.g., "AWS::S3::Bucket", "AWS::RDS::DBInstance")
        region: AWS region to use (e.g., "us-east-1", "us-west-2")

    Returns:
        A list of resource identifiers
    """
    if not resource_type:
        raise ClientError('Please provide a resource type (e.g., AWS::S3::Bucket)')

    cloudcontrol = get_aws_client('cloudcontrol', region)
    paginator = cloudcontrol.get_paginator('list_resources')

    results = []
    page_iterator = paginator.paginate(TypeName=resource_type)
    try:
        for page in page_iterator:
            results.extend(page['ResourceDescriptions'])
    except Exception as e:
        raise handle_aws_api_error(e)

    return [response['Identifier'] for response in results]


@mcp.tool()
async def get_resource(
    resource_type: str = Field(
        description='The AWS resource type (e.g., "AWS::S3::Bucket", "AWS::RDS::DBInstance")'
    ),
    identifier: str = Field(
        description='The primary identifier of the resource to get (e.g., bucket name for S3 buckets)'
    ),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
) -> dict:
    """Get details of a specific AWS resource.

    IMPORTANT: Always call get_aws_account_info() first and display the AWS account ID and region
    to the user before retrieving resource details.

    Parameters:
        resource_type: The AWS resource type (e.g., "AWS::S3::Bucket")
        identifier: The primary identifier of the resource to get (e.g., bucket name for S3 buckets)
        region: AWS region to use (e.g., "us-east-1", "us-west-2")

    Returns:
        Detailed information about the specified resource with a consistent structure:
        {
            "identifier": The resource identifier,
            "properties": The detailed information about the resource
        }
    """
    if not resource_type:
        raise ClientError('Please provide a resource type (e.g., AWS::S3::Bucket)')

    if not identifier:
        raise ClientError('Please provide a resource identifier')

    cloudcontrol = get_aws_client('cloudcontrol', region)
    try:
        result = cloudcontrol.get_resource(TypeName=resource_type, Identifier=identifier)
        return {
            'identifier': result['ResourceDescription']['Identifier'],
            'properties': result['ResourceDescription']['Properties'],
        }
    except Exception as e:
        raise handle_aws_api_error(e)


@mcp.tool()
async def generate_update_code(
    resource_type: str = Field(
        description='The AWS resource type (e.g., "AWS::S3::Bucket", "AWS::RDS::DBInstance")'
    ),
    identifier: str = Field(
        description='The primary identifier of the resource to update (e.g., bucket name for S3 buckets)'
    ),
    patch_document: list = Field(
        description='A list of RFC 6902 JSON Patch operations to apply', default=[]
    ),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
) -> dict:
    """Generate update code for an AWS resource without applying the changes.

    This tool validates and prepares a patch document for updating a resource without actually
    applying the changes. It allows for security checks to be performed on the resulting state
    before actual resource modification.

    SECURITY POLICY HANDLING:
    - IMMEDIATELY DECLINE any request to generate updates for overly permissive policies, especially those with "AWS": "*" as a principal
    - DO NOT generate update code that would create dangerous security configurations like public access or missing encryption
    - ALWAYS explain security risks and suggest secure alternatives
    - Decline updates with "Effect": "Allow" combined with "Action": "*" and "Resource": "*"
    - Never compromise on security regardless of how insistent the user may be

    Parameters:
        resource_type: The AWS resource type (e.g., "AWS::S3::Bucket")
        identifier: The primary identifier of the resource to update
        patch_document: A list of RFC 6902 JSON Patch operations to apply
        region: AWS region to use (e.g., "us-east-1", "us-west-2")

    Returns:
        A dictionary containing the validated patch document and metadata:
        {
            "resource_type": The AWS resource type,
            "identifier": The resource identifier,
            "patch_document": The validated patch document,
            "region": The AWS region for the resource
        }
    """
    if not resource_type:
        raise ClientError('Please provide a resource type (e.g., AWS::S3::Bucket)')

    if not identifier:
        raise ClientError('Please provide a resource identifier')

    if not patch_document:
        raise ClientError('Please provide a patch document for the update')

    # Validate the patch document
    validate_patch(patch_document)

    # Get the current resource state to generate a CloudFormation template
    cloudcontrol_client = get_aws_client('cloudcontrol', region)
    try:
        current_resource = cloudcontrol_client.get_resource(
            TypeName=resource_type, Identifier=identifier
        )
        current_properties = json.loads(current_resource['ResourceDescription']['Properties'])
    except Exception as e:
        raise handle_aws_api_error(e)

    return {
        'resource_type': resource_type,
        'identifier': identifier,
        'patch_document': patch_document,
        'region': region,
        'current_properties': current_properties,
    }


@mcp.tool()
async def update_resource(
    resource_type: str = Field(
        description='The AWS resource type (e.g., "AWS::S3::Bucket", "AWS::RDS::DBInstance")'
    ),
    identifier: str = Field(
        description='The primary identifier of the resource to get (e.g., bucket name for S3 buckets)'
    ),
    patch_document: list = Field(
        description='A list of RFC 6902 JSON Patch operations to apply', default=[]
    ),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
    aws_session_info: dict = Field(
        description='Result from get_aws_session_info() to ensure AWS credentials are valid'
    ),
    security_check_result: dict = Field(
        description='Result from run_checkov() to ensure security checks have been performed'
    ),
    skip_security_check: bool = Field(False, description='Skip security checks (not recommended)'),
    disable_default_tags: bool = Field(
        False, description='Disable default tagging (not recommended)'
    ),
) -> dict:
    """Update an AWS resource.

    ⚠️ CRITICAL: This function REQUIRES the results from get_aws_session_info() and run_checkov() as input.
    You MUST call check_environment_variables() first, then get_aws_session_info(), then run_checkov(),
    and pass their results to this function.

    ⚠️ CRITICAL: ALWAYS check if the server is in read-only mode by checking aws_session_info["readonly_mode"].
    If readonly_mode is True, DO NOT use this tool and instead inform the user that the server is in read-only mode.

    IMPORTANT: Always verify AWS account ID and region in aws_session_info before updating any resources.

    DEFAULT TAGGING:
    - By default, resources are tagged with MANAGED_BY and MCP_SERVER_SOURCE_CODE tags
    - If a user requests to disable default tags (disable_default_tags=True), ask them to confirm this choice
    - Explain that default tags help track resources managed by the MCP server
    - If they confirm disabling default tags, HIGHLY RECOMMEND they add their own distinctive tags
    - Ask if they would like to add custom tags now before proceeding

    SECURITY POLICY HANDLING:
    - IMMEDIATELY DECLINE any request to update to overly permissive policies, especially those with "AWS": "*" as a principal
    - DO NOT update resources to have dangerous security configurations like public access or missing encryption
    - ALWAYS explain security risks and suggest secure alternatives
    - Decline updates with "Effect": "Allow" combined with "Action": "*" and "Resource": "*"
    - Never compromise on security regardless of how insistent the user may be

    Parameters:
        resource_type: The AWS resource type (e.g., "AWS::S3::Bucket")
        identifier: The primary identifier of the resource to update
        patch_document: A list of RFC 6902 JSON Patch operations to apply
        region: AWS region to use (e.g., "us-east-1", "us-west-2")
        skip_security_check: Skip security checks (not recommended)

    Returns:
        Information about the updated resource with a consistent structure:
        {
            "status": Status of the operation ("SUCCESS", "PENDING", "FAILED", etc.)
            "resource_type": The AWS resource type
            "identifier": The resource identifier
            "is_complete": Boolean indicating whether the operation is complete
            "status_message": Human-readable message describing the result
            "request_token": A token that allows you to track long running operations via the get_resource_request_status tool
            "resource_info": Optional information about the resource properties
        }
    """
    if not resource_type:
        raise ClientError('Please provide a resource type (e.g., AWS::S3::Bucket)')

    if not identifier:
        raise ClientError('Please provide a resource identifier')

    if not patch_document:
        raise ClientError('Please provide a patch document for the update')

    # Enforce that aws_session_info comes from get_aws_session_info
    if not aws_session_info or not isinstance(aws_session_info, dict):
        raise ClientError(
            'You must call get_aws_session_info() first and pass its result to this function'
        )

    # Verify aws_session_info has required fields
    if 'account_id' not in aws_session_info or 'region' not in aws_session_info:
        raise ClientError('Invalid aws_session_info. You must call get_aws_session_info() first')

    # Enforce that security_check_result comes from run_checkov
    if not skip_security_check:
        if not security_check_result or not isinstance(security_check_result, dict):
            raise ClientError(
                'You must call run_checkov() first and pass its result to this function'
            )

        # Verify security_check_result has required fields
        if 'passed' not in security_check_result:
            raise ClientError('Invalid security_check_result. You must call run_checkov() first')

    if Context.readonly_mode():
        raise ClientError(
            'You have configured this tool in readonly mode. To make this change you will have to update your configuration.'
        )

    validate_patch(patch_document)
    cloudcontrol_client = get_aws_client('cloudcontrol', region)

    # Check if security checks are enabled via environment variable
    security_checks_enabled = environ.get('SECURITY_CHECKS', 'enabled').lower() == 'enabled'

    if security_checks_enabled and not skip_security_check:
        try:
            # Get the current resource state
            current_resource = cloudcontrol_client.get_resource(
                TypeName=resource_type, Identifier=identifier
            )
            current_properties = json.loads(current_resource['ResourceDescription']['Properties'])

            # Generate a CloudFormation template for security scanning
            cf_template = {
                'AWSTemplateFormatVersion': '2010-09-09',
                'Resources': {
                    'Resource': {'Type': resource_type, 'Properties': current_properties}
                },
            }

            # Run security checks using Checkov
            checkov_result = await run_checkov(
                content=cf_template, file_type='json', framework='cloudformation'
            )

            # If security checks failed, raise an error
            if not checkov_result.get('passed', False):
                failed_checks = checkov_result.get('failed_checks', [])
                if failed_checks:
                    # Check for high severity issues
                    high_severity_issues = [
                        check
                        for check in failed_checks
                        if check.get('severity')
                        and check.get('severity', '').upper() in ['HIGH', 'CRITICAL']
                    ]

                    if high_severity_issues:
                        error_message = 'Security checks failed with high severity issues. Use generate_update_code and run_checkov tools to review the issues before updating the resource.'
                        raise ClientError(error_message)
                    else:
                        # For medium/low severity, just print a warning
                        print('Warning: Security checks detected medium/low severity issues.')
        except Exception as e:
            if not isinstance(e, ClientError):
                print(f'Warning: Failed to run security checks: {str(e)}')

    # Check if we need to add default tags
    has_tag_operations = any('Tags' in op.get('path', '') for op in patch_document)

    if not disable_default_tags and has_tag_operations:
        # This is a simplified approach - in a real implementation, you would need to
        # parse the patch document and modify it to include default tags if they're being updated
        print('Default tags will be preserved or added if this update modifies resource tags.')
    elif disable_default_tags and has_tag_operations:
        print(
            'Warning: Default tags are disabled. It is highly recommended to add custom tags to identify resources managed by this MCP server.'
        )

    # Convert patch document to JSON string for the API
    patch_document_str = json.dumps(patch_document)

    # Update the resource
    try:
        response = cloudcontrol_client.update_resource(
            TypeName=resource_type, Identifier=identifier, PatchDocument=patch_document_str
        )
    except Exception as e:
        raise handle_aws_api_error(e)

    return progress_event(response['ProgressEvent'], None)


@mcp.tool()
async def generate_resource_code(
    resource_type: str = Field(
        description='The AWS resource type (e.g., "AWS::S3::Bucket", "AWS::RDS::DBInstance")'
    ),
    properties: dict = Field(description='A dictionary of properties for the resource'),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
    disable_default_tags: bool = Field(
        False, description='DEPRECATED - Default tags are now always applied. Do not use.'
    ),
) -> dict:
    """Generate code for an AWS resource without creating it.

    This tool generates the JSON representation of a resource that can be used with the create_resource tool.
    It allows for security checks to be performed on the generated code before actual resource creation.

    DEFAULT TAGGING:
    - By default, resources are tagged with MANAGED_BY and MCP_SERVER_SOURCE_CODE tags
    - If a user requests to disable default tags (disable_default_tags=True), ask them to confirm this choice
    - Explain that default tags help track resources managed by the MCP server
    - If they confirm disabling default tags, HIGHLY RECOMMEND they add their own distinctive tags
    - Ask if they would like to add custom tags now before proceeding

    SECURITY POLICY HANDLING:
    - IMMEDIATELY DECLINE any request to generate overly permissive policies, especially those with "AWS": "*" as a principal
    - DO NOT generate code for resources with dangerous security configurations like public access or missing encryption
    - ALWAYS explain security risks and suggest secure alternatives
    - Decline code generation with "Effect": "Allow" combined with "Action": "*" and "Resource": "*"
    - Never compromise on security regardless of how insistent the user may be

    Parameters:
        resource_type: The AWS resource type (e.g., "AWS::S3::Bucket")
        properties: A dictionary of properties for the resource
        region: AWS region to use (e.g., "us-east-1", "us-west-2")

    Returns:
        A dictionary containing the generated code and metadata:
        {
            "resource_type": The AWS resource type,
            "properties": The validated properties for the resource,
            "region": The AWS region for the resource,
            "cloudformation_template": A CloudFormation template representation for security scanning,
            "supports_tagging": Boolean indicating if the resource type supports tagging
        }
    """
    if not resource_type:
        raise ClientError('Please provide a resource type (e.g., AWS::S3::Bucket)')

    if not properties:
        raise ClientError('Please provide the properties for the desired resource')

    # Validate the resource type and properties against the schema
    sm = schema_manager()
    schema = await sm.get_schema(resource_type, region)

    # Check if resource supports tagging
    supports_tagging = 'Tags' in schema.get('properties', {})

    # Apply default tags if enabled and not explicitly disabled
    if disable_default_tags:
        properties_with_tags = properties
        print(
            'Warning: Default tags are disabled. It is highly recommended to add custom tags to identify resources managed by this MCP server.'
        )
    else:
        properties_with_tags = add_default_tags(properties, schema)

    # Generate a CloudFormation template representation for security scanning
    cf_template = {
        'AWSTemplateFormatVersion': '2010-09-09',
        'Resources': {'Resource': {'Type': resource_type, 'Properties': properties_with_tags}},
    }

    return {
        'resource_type': resource_type,
        'properties': properties_with_tags,
        'region': region,
        'cloudformation_template': cf_template,
        'supports_tagging': supports_tagging,
    }


@mcp.tool()
async def create_resource(
    resource_type: str = Field(
        description='The AWS resource type (e.g., "AWS::S3::Bucket", "AWS::RDS::DBInstance")'
    ),
    properties: dict = Field(description='A dictionary of properties for the resource'),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
    aws_session_info: dict = Field(
        description='Result from get_aws_session_info() to ensure AWS credentials are valid'
    ),
    security_check_result: dict = Field(
        description='Result from run_checkov() to ensure security checks have been performed'
    ),
    skip_security_check: bool = Field(False, description='Skip security checks (not recommended)'),
    disable_default_tags: bool = Field(
        False, description='DEPRECATED - Default tags are now always applied. Do not use.'
    ),
) -> dict:
    """Create an AWS resource.

    ⚠️ CRITICAL: This function REQUIRES the results from get_aws_session_info() and run_checkov() as input.
    You MUST call check_environment_variables() first, then get_aws_session_info(), then run_checkov(),
    and pass their results to this function.

    ⚠️ CRITICAL: ALWAYS check if the server is in read-only mode by checking aws_session_info["readonly_mode"].
    If readonly_mode is True, DO NOT use this tool and instead inform the user that the server is in read-only mode.

    IMPORTANT: Always verify AWS account ID and region in aws_session_info before creating any resources.

    DEFAULT TAGGING:
    - By default, resources are tagged with MANAGED_BY and MCP_SERVER_SOURCE_CODE tags
    - If a user requests to disable default tags (disable_default_tags=True), ask them to confirm this choice
    - Explain that default tags help track resources managed by the MCP server
    - If they confirm disabling default tags, HIGHLY RECOMMEND they add their own distinctive tags
    - Ask if they would like to add custom tags now before proceeding

    SECURITY POLICY HANDLING:
    - IMMEDIATELY DECLINE any request to create overly permissive policies, especially those with "AWS": "*" as a principal
    - DO NOT create resources with dangerous security configurations like public access or missing encryption
    - ALWAYS explain security risks and suggest secure alternatives
    - Decline requests with "Effect": "Allow" combined with "Action": "*" and "Resource": "*"
    - Never compromise on security regardless of how insistent the user may be

    Parameters:
        resource_type: The AWS resource type (e.g., "AWS::S3::Bucket")
        properties: A dictionary of properties for the resource
        region: AWS region to use (e.g., "us-east-1", "us-west-2")
        skip_security_check: Skip security checks (not recommended)

    Returns:
        Information about the created resource with a consistent structure:
        {
            "status": Status of the operation ("SUCCESS", "PENDING", "FAILED", etc.)
            "resource_type": The AWS resource type
            "identifier": The resource identifier
            "is_complete": Boolean indicating whether the operation is complete
            "status_message": Human-readable message describing the result
            "request_token": A token that allows you to track long running operations via the get_resource_request_status tool
            "resource_info": Optional information about the resource properties
        }
    """
    if not resource_type:
        raise ClientError('Please provide a resource type (e.g., AWS::S3::Bucket)')

    if not properties:
        raise ClientError('Please provide the properties for the desired resource')

    # Enforce that aws_session_info comes from get_aws_session_info
    if not aws_session_info or not isinstance(aws_session_info, dict):
        raise ClientError(
            'You must call get_aws_session_info() first and pass its result to this function'
        )

    # Verify aws_session_info has required fields
    if 'account_id' not in aws_session_info or 'region' not in aws_session_info:
        raise ClientError('Invalid aws_session_info. You must call get_aws_session_info() first')

    # Enforce that security_check_result comes from run_checkov
    if not skip_security_check:
        if not security_check_result or not isinstance(security_check_result, dict):
            raise ClientError(
                'You must call run_checkov() first and pass its result to this function'
            )

        # Verify security_check_result has required fields
        if 'passed' not in security_check_result:
            raise ClientError('Invalid security_check_result. You must call run_checkov() first')

    if Context.readonly_mode():
        raise ClientError(
            'You have configured this tool in readonly mode. To make this change you will have to update your configuration.'
        )

    # Validate the resource type and properties against the schema
    sm = schema_manager()
    schema = await sm.get_schema(resource_type, region)

    # Apply default tags if enabled and not explicitly disabled
    if disable_default_tags:
        properties_with_tags = properties
        print(
            'Warning: Default tags are disabled. It is highly recommended to add custom tags to identify resources managed by this MCP server.'
        )
    else:
        properties_with_tags = add_default_tags(properties, schema)

    # Check if security checks are enabled via environment variable
    security_checks_enabled = environ.get('SECURITY_CHECKS', 'enabled').lower() == 'enabled'

    # If security checks are enabled and not explicitly skipped, generate a CloudFormation template
    # for security scanning
    if security_checks_enabled and not skip_security_check:
        # Generate CloudFormation template for security scanning
        cf_template = {
            'AWSTemplateFormatVersion': '2010-09-09',
            'Resources': {'Resource': {'Type': resource_type, 'Properties': properties_with_tags}},
        }

        # Run security checks using Checkov
        checkov_result = await run_checkov(
            content=cf_template, file_type='json', framework='cloudformation'
        )

        # If security checks failed, raise an error
        if not checkov_result.get('passed', False):
            failed_checks = checkov_result.get('failed_checks', [])
            if failed_checks:
                # Check for high severity issues
                high_severity_issues = [
                    check
                    for check in failed_checks
                    if check.get('severity')
                    and check.get('severity', '').upper() in ['HIGH', 'CRITICAL']
                ]

                if high_severity_issues:
                    error_message = 'Security checks failed with high severity issues. Use generate_resource_code and run_checkov tools to review the issues before creating the resource.'
                    raise ClientError(error_message)
                else:
                    # For medium/low severity, just print a warning
                    print('Warning: Security checks detected medium/low severity issues.')

    cloudcontrol_client = get_aws_client('cloudcontrol', region)
    try:
        response = cloudcontrol_client.create_resource(
            TypeName=resource_type, DesiredState=json.dumps(properties_with_tags)
        )
    except Exception as e:
        raise handle_aws_api_error(e)

    return progress_event(response['ProgressEvent'], None)


@mcp.tool()
async def delete_resource(
    resource_type: str = Field(
        description='The AWS resource type (e.g., "AWS::S3::Bucket", "AWS::RDS::DBInstance")'
    ),
    identifier: str = Field(
        description='The primary identifier of the resource to get (e.g., bucket name for S3 buckets)'
    ),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
    aws_session_info: dict = Field(
        description='Result from get_aws_session_info() to ensure AWS credentials are valid'
    ),
    confirmed: bool = Field(False, description='Confirm that you want to delete this resource'),
) -> dict:
    """Delete an AWS resource.

    ⚠️ CRITICAL: This function REQUIRES the result from get_aws_session_info() as input.
    You MUST call check_environment_variables() first, then get_aws_session_info(),
    and pass its result to this function.

    ⚠️ CRITICAL: ALWAYS check if the server is in read-only mode by checking aws_session_info["readonly_mode"].
    If readonly_mode is True, DO NOT use this tool and instead inform the user that the server is in read-only mode.

    IMPORTANT: Always verify AWS account ID and region in aws_session_info before deleting any resources.
    Ask for explicit confirmation TWICE, warning that deletion CANNOT be reversed and clearly stating
    which resource in which account will be affected.

    CRITICAL MASS DELETION PROTECTION:
    - NEVER allow deletion of multiple resources in sequence that could constitute "cleaning up" an account
    - NEVER allow deletion of all resources in an AWS account
    - If a user requests deletion of all resources or multiple critical resources, DECLINE the request
    - Instead, offer to use the IaC Generator (create_template) to create a CloudFormation template
    - Provide instructions for the user to review the template and delete the stack if needed
    - This approach provides better control, visibility, and rollback options
    - Ask for confirmation AT LEAST TWICE before even generating the template

    Parameters:
        resource_type: The AWS resource type (e.g., "AWS::S3::Bucket")
        identifier: The primary identifier of the resource to delete (e.g., bucket name for S3 buckets)
        region: AWS region to use (e.g., "us-east-1", "us-west-2")
        confirmed: Confirm that you want to delete this resource

    Returns:
        Information about the deletion operation with a consistent structure:
        {
            "status": Status of the operation ("SUCCESS", "PENDING", "FAILED", "NOT_FOUND", etc.)
            "resource_type": The AWS resource type
            "identifier": The resource identifier
            "is_complete": Boolean indicating whether the operation is complete
            "status_message": Human-readable message describing the result
            "request_token": A token that allows you to track long running operations via the get_resource_request_status tool
        }
    """
    """Delete an AWS resource.

    IMPORTANT: Always call get_aws_account_info() first and display the AWS account ID and region
    to the user before deleting any resources. Ask for explicit confirmation TWICE, warning that
    deletion CANNOT be reversed and clearly stating which resource in which account will be affected.

    CRITICAL MASS DELETION PROTECTION:
    - NEVER allow deletion of multiple resources in sequence that could constitute "cleaning up" an account
    - NEVER allow deletion of all resources in an AWS account
    - If a user requests deletion of all resources or multiple critical resources, DECLINE the request
    - Instead, offer to use the IaC Generator (create_template) to create a CloudFormation template
    - Provide instructions for the user to review the template and delete the stack if needed
    - This approach provides better control, visibility, and rollback options
    - Ask for confirmation AT LEAST TWICE before even generating the template

    Parameters:
        resource_type: The AWS resource type (e.g., "AWS::S3::Bucket")
        identifier: The primary identifier of the resource to delete (e.g., bucket name for S3 buckets)
        region: AWS region to use (e.g., "us-east-1", "us-west-2")
        confirmed: Confirm that you want to delete this resource

    Returns:
        Information about the deletion operation with a consistent structure:
        {
            "status": Status of the operation ("SUCCESS", "PENDING", "FAILED", "NOT_FOUND", etc.)
            "resource_type": The AWS resource type
            "identifier": The resource identifier
            "is_complete": Boolean indicating whether the operation is complete
            "status_message": Human-readable message describing the result
            "request_token": A token that allows you to track long running operations via the get_resource_request_status tool
        }
    """
    if not resource_type:
        raise ClientError('Please provide a resource type (e.g., AWS::S3::Bucket)')

    if not identifier:
        raise ClientError('Please provide a resource identifier')

    if not confirmed:
        raise ClientError(
            'Please confirm the deletion by setting confirmed=True to proceed with resource deletion.'
        )

    # Enforce that aws_session_info comes from get_aws_session_info
    if not aws_session_info or not isinstance(aws_session_info, dict):
        raise ClientError(
            'You must call get_aws_session_info() first and pass its result to this function'
        )

    # Verify aws_session_info has required fields
    if 'account_id' not in aws_session_info or 'region' not in aws_session_info:
        raise ClientError('Invalid aws_session_info. You must call get_aws_session_info() first')

    if Context.readonly_mode():
        raise ClientError(
            'You have configured this tool in readonly mode. To make this change you will have to update your configuration.'
        )

    cloudcontrol_client = get_aws_client('cloudcontrol', region)
    try:
        response = cloudcontrol_client.delete_resource(
            TypeName=resource_type, Identifier=identifier
        )
    except Exception as e:
        raise handle_aws_api_error(e)

    return progress_event(response['ProgressEvent'], None)


@mcp.tool()
async def get_resource_request_status(
    request_token: str = Field(
        description='The request_token returned from the long running operation'
    ),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
) -> dict:
    """Get the status of a long running operation with the request token.

    Args:
        request_token: The request_token returned from the long running operation
        region: AWS region to use (e.g., "us-east-1", "us-west-2")

    Returns:
        Detailed information about the request status structured as
        {
            "status": Status of the operation ("SUCCESS", "PENDING", "FAILED", "NOT_FOUND", etc.)
            "resource_type": The AWS resource type
            "identifier": The resource identifier
            "is_complete": Boolean indicating whether the operation is complete
            "status_message": Human-readable message describing the result
            "request_token": A token that allows you to track long running operations via the get_resource_request_status tool
            "error_code": A code associated with any errors if the request failed
            "retry_after": A duration to wait before retrying the request
        }
    """
    if not request_token:
        raise ClientError('Please provide a request token to track the request')

    cloudcontrol_client = get_aws_client('cloudcontrol', region)
    try:
        response = cloudcontrol_client.get_resource_request_status(
            RequestToken=request_token,
        )
    except Exception as e:
        raise handle_aws_api_error(e)

    return progress_event(response['ProgressEvent'], response.get('HooksProgressEvent', None))


@mcp.tool()
async def create_template_tool(
    template_name: str | None = Field(None, description='Name for the generated template'),
    resources: list | None = Field(
        None,
        description="List of resources to include in the template, each with 'ResourceType' and 'ResourceIdentifier'",
    ),
    output_format: str = Field(
        'YAML', description='Output format for the template (JSON or YAML)'
    ),
    deletion_policy: str = Field(
        'RETAIN',
        description='Default DeletionPolicy for resources in the template (RETAIN, DELETE, or SNAPSHOT)',
    ),
    update_replace_policy: str = Field(
        'RETAIN',
        description='Default UpdateReplacePolicy for resources in the template (RETAIN, DELETE, or SNAPSHOT)',
    ),
    template_id: str | None = Field(
        None,
        description='ID of an existing template generation process to check status or retrieve template',
    ),
    save_to_file: str | None = Field(
        None, description='Path to save the generated template to a file'
    ),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
    convert_to: str | None = Field(
        None,
        description='Convert the CloudFormation template to another IaC format (terraform, cdk-typescript, cdk-python)',
    ),
) -> dict:
    """Create a CloudFormation template from existing resources using the IaC Generator API.

    This tool allows you to generate CloudFormation templates from existing AWS resources
    that are not already managed by CloudFormation. The template can be generated in CloudFormation
    format (YAML/JSON) and optionally converted to other IaC formats like Terraform or AWS CDK.

    The template generation process is asynchronous, so you can check the status of the process
    and retrieve the template once it's complete. You can pass up to 500 resources at a time.

    IMPORTANT FOR RESOURCE MANAGEMENT:
    - This is the PREFERRED method for managing multiple resources or cleaning up infrastructure
    - When a user wants to delete multiple resources or clean up an account, use this tool instead of delete_resource
    - Generate a template of existing resources, which the user can review and delete as a CloudFormation stack
    - This provides better control, visibility, and rollback options than direct deletion
    - Always ask for confirmation AT LEAST TWICE before generating a template for deletion purposes
    - Clearly explain the risks and implications of deleting infrastructure

    After creating or updating resources, consider using this tool to generate a template of
    the infrastructure for documentation or future deployments.

    Examples:
    1. Start template generation for an S3 bucket:
       create_template(
           template_name="my-template",
           resources=[{"ResourceType": "AWS::S3::Bucket", "ResourceIdentifier": {"BucketName": "my-bucket"}}],
           deletion_policy="RETAIN",
           update_replace_policy="RETAIN"
       )

    2. Check status of template generation:
       create_template(template_id="arn:aws:cloudformation:us-east-1:123456789012:generatedtemplate/abcdef12-3456-7890-abcd-ef1234567890")

    3. Retrieve and save generated template:
       create_template(
           template_id="arn:aws:cloudformation:us-east-1:123456789012:generatedtemplate/abcdef12-3456-7890-abcd-ef1234567890",
           save_to_file="/path/to/template.yaml",
           output_format="YAML"
       )

    4. Generate a template and convert to Terraform:
       create_template(
           template_name="my-template",
           resources=[{"ResourceType": "AWS::S3::Bucket", "ResourceIdentifier": {"BucketName": "my-bucket"}}],
           convert_to="terraform"
       )
    """
    return await create_template(
        template_name=template_name,
        resources=resources,
        output_format=output_format,
        deletion_policy=deletion_policy,
        update_replace_policy=update_replace_policy,
        template_id=template_id,
        save_to_file=save_to_file,
        region_name=region,
    )


def _check_checkov_installed() -> dict:
    """Check if Checkov is installed and install it if not.

    Returns:
        A dictionary with status information:
        {
            "installed": True/False,
            "message": Description of what happened,
            "needs_user_action": True/False
        }
    """
    try:
        # Check if Checkov is already installed
        subprocess.run(
            ['checkov', '--version'],
            capture_output=True,
            text=True,
            check=False,
        )
        return {
            'installed': True,
            'message': 'Checkov is already installed',
            'needs_user_action': False,
        }
    except FileNotFoundError:
        # Attempt to install Checkov
        try:
            # Install Checkov using pip
            print('Checkov not found, attempting to install...')
            subprocess.run(
                ['pip', 'install', 'checkov'],
                capture_output=True,
                text=True,
                check=True,
            )
            print('Successfully installed Checkov')
            return {
                'installed': True,
                'message': 'Checkov was automatically installed',
                'needs_user_action': False,
            }
        except subprocess.CalledProcessError as e:
            # Installation failed
            return {
                'installed': False,
                'message': f'Failed to install Checkov: {e}. Please install it manually with "pip install checkov".',
                'needs_user_action': True,
            }


@mcp.tool()
async def run_checkov(
    content: Any = Field(
        description='The IaC content to scan (JSON, YAML, or HCL) as string or dict'
    ),
    file_type: Literal['json', 'yaml', 'hcl'] = Field(
        description='The type of IaC file (json, yaml, or hcl)'
    ),
    framework: str | None = Field(
        description='The framework to scan (cloudformation, terraform, kubernetes, etc.)',
        default=None,
    ),
) -> dict:
    """Run Checkov security and compliance scanner on IaC content.

    This tool runs Checkov to scan Infrastructure as Code (IaC) content for security and compliance issues.
    It supports CloudFormation templates (JSON/YAML), Terraform files (HCL), and other IaC formats.

    CRITICAL: After EVERY call to run_checkov(), you MUST display the security findings to the user.
    This is mandatory for EVERY invocation to ensure users are always aware of potential security
    issues in their infrastructure code.

    If a user asks you to stop showing these findings, politely explain that it's a security
    best practice to ensure they're always aware of potential security risks, and ask if
    they're sure they want to disable this important safety feature.

    Parameters:
        content: The IaC content to scan as a string
        file_type: The type of IaC file (json, yaml, or hcl)
        framework: Optional framework to scan (cloudformation, terraform, kubernetes, etc.)
                  If not specified, Checkov will auto-detect the framework

    Returns:
        A dictionary containing the scan results with the following structure:
        {
            "passed": Boolean indicating if all checks passed,
            "failed_checks": List of failed security checks,
            "passed_checks": List of passed security checks,
            "summary": Summary of the scan results
        }

    Examples:
        1. Scan a CloudFormation template:
           run_checkov(
               content='{"Resources": {"S3Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}',
               file_type='json',
               framework='cloudformation'
           )

        2. Scan a Terraform file:
           run_checkov(
               content='resource "aws_s3_bucket" "example" { bucket = "example" }',
               file_type='hcl',
               framework='terraform'
           )
    """
    # Check if Checkov is installed
    checkov_status = _check_checkov_installed()
    if not checkov_status['installed']:
        return {
            'passed': False,
            'error': 'Checkov is not installed',
            'summary': {'error': 'Checkov not installed'},
            'message': checkov_status['message'],
            'requires_confirmation': checkov_status['needs_user_action'],
            'options': [
                {'option': 'install_help', 'description': 'Get help installing Checkov'},
                {'option': 'proceed_without', 'description': 'Proceed without security checks'},
                {'option': 'cancel', 'description': 'Cancel the operation'},
            ],
        }

    # Map file types to extensions
    file_extensions = {'json': '.json', 'yaml': '.yaml', 'hcl': '.tf'}

    if file_type not in file_extensions:
        raise ClientError(
            f'Unsupported file type: {file_type}. Supported types are: json, yaml, hcl'
        )

    # Ensure content is a string
    if not isinstance(content, str):
        try:
            content = json.dumps(content)
        except Exception as e:
            return {
                'passed': False,
                'error': f'Content must be a valid JSON string or object: {str(e)}',
                'summary': {'error': 'Invalid content format'},
            }

    # Create a temporary file with the content
    with tempfile.NamedTemporaryFile(suffix=file_extensions[file_type], delete=False) as temp_file:
        temp_file.write(content.encode('utf-8'))
        temp_file_path = temp_file.name

    try:
        # Build the checkov command
        cmd = ['checkov', '-f', temp_file_path, '--output', 'json']

        # Add framework if specified
        if framework:
            cmd.extend(['--framework', framework])

        # Run checkov
        process = subprocess.run(cmd, capture_output=True, text=True)

        # Parse the output
        if process.returncode == 0:
            # All checks passed
            return {
                'passed': True,
                'failed_checks': [],
                'passed_checks': json.loads(process.stdout) if process.stdout else [],
                'summary': {'passed': True, 'message': 'All security checks passed'},
            }
        elif process.returncode == 1:  # Return code 1 means vulnerabilities were found
            # Some checks failed
            try:
                results = json.loads(process.stdout) if process.stdout else {}
                failed_checks = results.get('results', {}).get('failed_checks', [])
                passed_checks = results.get('results', {}).get('passed_checks', [])
                summary = results.get('summary', {})

                return {
                    'passed': False,
                    'failed_checks': failed_checks,
                    'passed_checks': passed_checks,
                    'summary': summary,
                }
            except json.JSONDecodeError:
                # Handle case where output is not valid JSON
                return {
                    'passed': False,
                    'error': 'Failed to parse Checkov output',
                    'stdout': process.stdout,
                    'stderr': process.stderr,
                }
        else:
            # Error running checkov
            return {
                'passed': False,
                'error': f'Checkov exited with code {process.returncode}',
                'stderr': process.stderr,
            }
    except Exception as e:
        return {'passed': False, 'error': str(e), 'message': 'Failed to run Checkov'}
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


@mcp.tool()
async def check_environment_variables() -> dict:
    """Check if required environment variables are set correctly.

    CRITICAL: ALWAYS call this function FIRST before any AWS operations to ensure
    the environment is properly configured.

    This tool checks if all required environment variables are set with proper values
    and returns their current configuration. Use this to help users troubleshoot
    credential issues before attempting any AWS operations.

    IMPORTANT: After checking the environment variables, ALWAYS display a summary of the
    current environment variables and their values to the user.

    ENVIRONMENT VARIABLES EXPLANATION:
    - AWS_REGION: The AWS region to use for all operations (e.g., "us-east-1")
    - AWS_PROFILE: The AWS profile name to use when AWS_CREDENTIAL_SOURCE is not 'env'
    - AWS_CREDENTIAL_SOURCE: How to obtain AWS credentials:
      * 'env' or 'environment': Use credentials from environment variables (AWS_ACCESS_KEY_ID, etc.)
      * 'profile': Use credentials from the specified AWS_PROFILE
      * 'sso': Use AWS SSO with the specified AWS_PROFILE

    - DEFAULT_TAGS: When 'enabled', automatically adds MANAGED_BY and MCP_SERVER_SOURCE_CODE tags
      to resources created or updated by the MCP server.

    IMPORTANT: If AWS_CREDENTIAL_SOURCE is set to anything other than 'env' or 'environment',
    you MUST inform the user that they need to include the name of an AWS profile since they
    are not using exported environment variables. Ask if they want help setting this up.
    If they acknowledge, ask them for the profile name. If they don't know, ask if they would
    like you to list the AWS profiles currently configured on their machine.

    Returns:
        A dictionary containing environment variable information:
        {
            "environment_variables": Dictionary of all relevant environment variables,
            "aws_profile": The AWS profile name being used,
            "aws_region": The AWS region being used,
            "aws_credential_source": The credential source being used,
            "default_tags_enabled": Whether default tagging is enabled,
            "properly_configured": Boolean indicating if the environment is properly configured,
            "needs_profile": Boolean indicating if a profile name is required but missing
        }
    """
    # Load all environment variables
    env_vars = {
        'AWS_PROFILE': environ.get('AWS_PROFILE', ''),
        'AWS_REGION': environ.get('AWS_REGION', 'us-east-1'),
        'AWS_CREDENTIAL_SOURCE': environ.get('AWS_CREDENTIAL_SOURCE', ''),
        'DEFAULT_TAGS': environ.get('DEFAULT_TAGS', 'enabled'),
    }

    # Check if required variables are set properly
    aws_profile = env_vars.get('AWS_PROFILE', '')
    aws_region = env_vars.get('AWS_REGION', 'us-east-1')
    aws_credential_source = env_vars.get('AWS_CREDENTIAL_SOURCE', '')
    default_tags = env_vars.get('DEFAULT_TAGS', 'enabled')

    # Determine if properly configured
    properly_configured = True
    needs_profile = False

    # If credential source is not 'env' or 'environment' and no profile is specified,
    # we need to inform the user that a profile is required
    if aws_credential_source.lower() not in ('env', 'environment', '') and not aws_profile:
        properly_configured = False
        needs_profile = True

    # For SSO, we need AWS_PROFILE to be set
    if aws_credential_source.lower() == 'sso' and not aws_profile:
        properly_configured = False
        needs_profile = True

    # For profile, we need AWS_PROFILE to be set
    if aws_credential_source.lower() == 'profile' and not aws_profile:
        properly_configured = False
        needs_profile = True

    # No session duration validation needed

    return {
        'environment_variables': env_vars,
        'aws_profile': aws_profile,
        'aws_region': aws_region,
        'aws_credential_source': aws_credential_source,
        'default_tags_enabled': default_tags.lower() != 'disabled',
        'properly_configured': properly_configured,
        'readonly_mode': Context.readonly_mode(),
        'needs_profile': needs_profile,
    }


def get_aws_profile_info():
    """Get information about the current AWS profile.

    Returns:
        A dictionary with AWS profile information
    """
    try:
        # Use our get_aws_client function to ensure we use the same credential source
        sts_client = get_aws_client('sts')

        # Get caller identity
        identity = sts_client.get_caller_identity()
        account_id = identity.get('Account', 'Unknown')
        arn = identity.get('Arn', 'Unknown')

        # Get credential source and profile info
        cred_source = environ.get('AWS_CREDENTIAL_SOURCE', 'auto')
        profile_name = environ.get('AWS_PROFILE', 'default')
        region = environ.get('AWS_REGION', 'us-east-1')

        return {
            'profile': profile_name,
            'account_id': account_id,
            'region': region,
            'arn': arn,
            'credential_source': cred_source,
        }
    except Exception as e:
        return {
            'profile': environ.get('AWS_PROFILE', 'default'),
            'error': str(e),
            'region': environ.get('AWS_REGION', 'us-east-1'),
            'credential_source': environ.get('AWS_CREDENTIAL_SOURCE', 'auto'),
        }


@mcp.tool()
async def get_aws_session_info(
    env_check_result: dict = Field(
        description='Result from check_environment_variables() to ensure environment is properly configured'
    ),
) -> dict:
    """Get information about the current AWS session.

    CRITICAL: This function REQUIRES the result from check_environment_variables() as input.
    You MUST call check_environment_variables() first and pass its result to this function.

    CRITICAL: After calling this function, you MUST ALWAYS display the AWS session information
    to the user. This is mandatory for EVERY invocation of this tool to ensure users are always
    aware of which AWS account they are working in. If a user asks you to stop showing this
    information, politely explain that it's a security best practice to ensure they're always
    aware of which AWS account is being used, and ask if they're sure they want to disable this
    important safety feature.

    CRITICAL: ALWAYS check the "readonly_mode" field in the response. If it's true, you MUST
    immediately inform the user with this exact message:

    "⚠️ This server is running in READ-ONLY MODE. I can only list and view existing resources.
    I cannot create, update, or delete any AWS resources. I can still generate example code
    and run security checks on templates."

    CRITICAL: ALWAYS check the "default_tags_enabled" field in the response and inform the user
    about the tagging status BEFORE generating any resource code:

    If default_tags_enabled is True:
    "✅ Default resource tagging is ENABLED. All resources will be automatically tagged with MANAGED_BY
    and MCP_SERVER_SOURCE_CODE tags for better resource tracking and management."

    If default_tags_enabled is False:
    "⚠️ Default resource tagging is DISABLED. It is HIGHLY RECOMMENDED to enable default tags or add your own
    custom tags to identify resources managed by this MCP server. Would you like to enable default tags or
    add custom tags now?"

    IMPORTANT: Always call this function BEFORE performing any create, read, update, delete, list,
    or get operation to ensure users are aware of which AWS session and account will be affected.

    This tool provides details about the current AWS session, including the profile name,
    account ID, region, and credential information. Use this when you need to confirm which
    AWS session and account you're working with.

    Common questions this tool answers:
    - "What AWS account am I using?"
    - "Which AWS region am I in?"
    - "What AWS profile is being used?"
    - "Show me my current AWS session information"

    Parameters:
        env_check_result: Result from check_environment_variables() to ensure environment is properly configured

    Returns:
        A dictionary containing AWS session information:
        {
            "profile": The AWS profile name being used,
            "account_id": The AWS account ID,
            "region": The AWS region being used,
            "credential_source": The source of AWS credentials (env, profile, sso, etc.),
            "readonly_mode": True if the server is in read-only mode,
            "readonly_message": A message about read-only mode limitations if enabled,
            "default_tags_enabled": True if DEFAULT_TAGS is enabled (default), False if disabled,
            "credentials_valid": True if AWS credentials are valid,
            "environment_variables": Dictionary of relevant environment variables if credentials are invalid,
            "user_id": The AWS user ID or role ID associated with the session,
            "arn": The ARN of the user or role associated with the session,
            "needs_profile": Boolean indicating if a profile name is required but missing
        }
    """
    # Verify that environment check was performed
    if not env_check_result or not isinstance(env_check_result, dict):
        raise ClientError(
            'You must call check_environment_variables() first and pass its result to this function'
        )

    # Verify that environment is properly configured
    if not env_check_result.get('properly_configured', False):
        raise ClientError(
            'Environment is not properly configured. Please fix the environment variables first.'
        )

    # Get environment variables from the check result
    env_vars = env_check_result.get('environment_variables', {})

    # Get AWS profile info
    info = get_aws_profile_info()

    # Add additional information
    info['readonly_mode'] = Context.readonly_mode()
    info['readonly_message'] = (
        """⚠️ This server is running in READ-ONLY MODE. I can only list and view existing resources.
    I cannot create, update, or delete any AWS resources. I can still generate example code
    and run security checks on templates."""
        if Context.readonly_mode()
        else ''
    )
    info['default_tags_enabled'] = env_vars.get('DEFAULT_TAGS', 'enabled').lower() != 'disabled'
    info['credentials_valid'] = 'error' not in info
    # Session duration and auto refresh session variables removed
    info['needs_profile'] = env_check_result.get('needs_profile', False)

    return info


@mcp.tool()
async def get_aws_account_info() -> dict:
    """Get information about the current AWS account being used.

    DEPRECATED: Use check_environment_variables() followed by get_aws_session_info() instead.

    This function is maintained for backward compatibility only.

    Common questions this tool answers:
    - "What AWS account am I using?"
    - "Which AWS region am I in?"
    - "What AWS profile is being used?"
    - "Show me my current AWS session information"

    Returns:
        A dictionary containing AWS account information:
        {
            "profile": The AWS profile name being used,
            "account_id": The AWS account ID,
            "region": The AWS region being used,
            "readonly_mode": True if the server is in read-only mode,
            "readonly_message": A message about read-only mode limitations if enabled,
            "default_tags_enabled": True if DEFAULT_TAGS is enabled (default), False if disabled
        }
    """
    # First check environment variables
    env_check = await check_environment_variables()

    # Then get session info if environment is properly configured
    if env_check['properly_configured']:
        return await get_aws_session_info(env_check_result=env_check)
    else:
        return {
            'error': 'Environment not properly configured',
            'environment_variables': env_check['environment_variables'],
            'properly_configured': False,
        }


def main():
    """Run the MCP server with CLI argument support."""
    parser = argparse.ArgumentParser(
        description='An AWS Labs Model Context Protocol (MCP) server for doing common cloudformation tasks and for managing your resources in your AWS account'
    )
    parser.add_argument(
        '--readonly',
        action=argparse.BooleanOptionalAction,
        help='Prevents the MCP server from performing mutating operations',
    )

    args = parser.parse_args()
    Context.initialize(args.readonly)

    # Display AWS profile information
    aws_info = get_aws_profile_info()
    print(f'AWS Profile: {aws_info.get("profile")}')
    print(f'AWS Account ID: {aws_info.get("account_id", "Unknown")}')
    print(f'AWS Region: {aws_info.get("region")}')

    # Output format display removed

    # Display read-only mode status
    if args.readonly:
        print('\n⚠️ READ-ONLY MODE ACTIVE ⚠️')
        print('The server will not perform any create, update, or delete operations.')

    mcp.run()


if __name__ == '__main__':
    main()
