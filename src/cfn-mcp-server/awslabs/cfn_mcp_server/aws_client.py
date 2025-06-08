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

import botocore.config
import sys
from awslabs.cfn_mcp_server.errors import ClientError
from boto3 import Session
from os import environ


session_config = botocore.config.Config(
    user_agent_extra='cfn-mcp-server/1.0.0',
)


def get_aws_client(service_name, region_name=None):
    """Create and return an AWS service client with dynamically detected credentials.

    This function implements a credential provider chain that tries different
    credential sources based on the AWS_CREDENTIAL_SOURCE environment variable:
    - 'env': Use environment variables (AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)
    - 'profile': Use the profile specified in AWS_PROFILE from ~/.aws/credentials
    - 'sso': Use AWS SSO token cache for the profile specified in AWS_PROFILE
    - 'instance': Use IAM role for Amazon EC2 / ECS task role / EKS pod identity
    - 'auto' (default): Use the default AWS credential provider chain

    Args:
        service_name: AWS service name (e.g., 'cloudcontrol', 'logs', 'marketplace-catalog')
        region_name: AWS region name (defaults to environment variable or 'us-east-1')

    Returns:
        Boto3 client for the specified service
    """
    # Default region handling
    if not region_name:
        region_name = environ.get('AWS_REGION', 'us-east-1')

    # Get credential source preference
    cred_source = environ.get('AWS_CREDENTIAL_SOURCE', 'auto').lower()
    
    # Credential detection and client creation
    try:
        if cred_source == 'env' or cred_source == 'environment':
            # Force use of environment variables
            print(f'Creating {service_name} client using environment variables')
            if not environ.get('AWS_ACCESS_KEY_ID') or not environ.get('AWS_SECRET_ACCESS_KEY'):
                raise ClientError('AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set when using environment credentials')
            session = Session(
                aws_access_key_id=environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=environ.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=environ.get('AWS_SESSION_TOKEN')
            )
        elif cred_source == 'profile':
            # Force use of profile from credentials file
            profile_name = environ.get('AWS_PROFILE')
            if not profile_name:
                raise ClientError('AWS_PROFILE environment variable must be set when using profile credential source')
            print(f'Creating {service_name} client using profile: {profile_name}')
            session = Session(profile_name=profile_name)
        elif cred_source == 'sso':
            # Use SSO token cache
            profile_name = environ.get('AWS_PROFILE')
            if not profile_name:
                raise ClientError('AWS_PROFILE environment variable must be set when using SSO credential source')
            print(f'Creating {service_name} client using SSO profile: {profile_name}')
            session = Session(profile_name=profile_name)
        elif cred_source == 'instance' or cred_source == 'role':
            # Force use of instance profile/container role
            print(f'Creating {service_name} client using instance profile/container role')
            session = Session(aws_access_key_id=None, aws_secret_access_key=None)
        else:  # 'auto' or any other value
            # Use default credential provider chain
            print(f'Creating {service_name} client using default AWS credential provider chain')
            session = Session()
        
        client = session.client(service_name, region_name=region_name, config=session_config)
        
        # Verify credentials by making a simple call if it's the STS service
        if service_name == 'sts':
            identity = client.get_caller_identity()
            print(f"Successfully authenticated as: {identity.get('Arn')}")
        
        print(f'Successfully created {service_name} client for region {region_name}')
        return client

    except Exception as e:
        print(f'Error creating {service_name} client: {str(e)}', file=sys.stderr)
        if 'ExpiredToken' in str(e):
            raise ClientError(
                'Your AWS credentials have expired. Please refresh them. '
                'Consider setting AWS_CREDENTIAL_SOURCE to specify which credential type to use.'
            )
        elif 'NoCredentialProviders' in str(e):
            raise ClientError(
                'No AWS credentials found. Please configure credentials using environment variables or AWS configuration. '
                'Set AWS_CREDENTIAL_SOURCE to "env", "profile", "sso", or "instance" to specify which credential type to use.'
            )
        else:
            raise ClientError(f'Error when loading client: {str(e)}')