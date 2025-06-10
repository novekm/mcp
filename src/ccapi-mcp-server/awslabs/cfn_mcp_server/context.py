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

from awslabs.ccapi_mcp_server.errors import ServerError


class Context:
    """A singleton which includes context for the MCP server such as startup parameters."""

    _instance = None
    aws_profile = None
    aws_account_id = None
    aws_region = None

    def __init__(self, readonly_mode: bool):
        """Initializes the context."""
        self._readonly_mode = readonly_mode

    @classmethod
    def readonly_mode(cls) -> bool:
        """If a the server was started up with the argument --readonly True, this will be set to True."""
        if cls._instance is None:
            raise ServerError('Context was not initialized')
        return cls._instance._readonly_mode

    @classmethod
    def is_readonly_mode(cls) -> str:
        """Returns a message about readonly mode if enabled, empty string otherwise."""
        if cls._instance is None:
            raise ServerError('Context was not initialized')
        if cls._instance._readonly_mode:
            return """
⚠️ READ-ONLY MODE ACTIVE ⚠️

This server is running in read-only mode. You can only:
- List and get information about existing resources
- Generate example code and templates
- Run security checks on IaC files

You CANNOT create, update, or delete any AWS resources.
"""
        return ''

    @classmethod
    def get_aws_info(cls):
        """Get AWS account information."""
        return {
            'profile': cls.aws_profile,
            'account_id': cls.aws_account_id,
            'region': cls.aws_region,
        }

    @classmethod
    def initialize(cls, readonly_mode: bool):
        """Create the singleton instance of the type."""
        cls._instance = cls(readonly_mode)
