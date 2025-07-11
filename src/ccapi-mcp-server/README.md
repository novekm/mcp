# Cloud Control API MCP Server

Model Context Protocol (MCP) server that enables LLMs to directly create and manage over 1,100 AWS resources through natural language using AWS Cloud Control API and Iac Generator with Infrastructure as Code best practices.

## Prerequisites

- All prerequisites listed in the [Installation and Setup](https://github.com/awslabs/mcp#installation-and-setup) section within the awslabs/mcp README should be satisfied
- Valid AWS credentials
- Ensure your IAM role or user has the necessary permissions (see [Security Considerations](#security-considerations))

## Features

- **Resource Creation**: Uses a declarative approach to create any of 1,100+ AWS resources through Cloud Control API
- **Resource Reading**: Reads all properties and attributes of specific AWS resources
- **Resource Updates**: Uses a declarative approach to apply changes to existing AWS resources
- **Resource Deletion**: Safely removes AWS resources with proper validation
- **Resource Listing**: Enumerates all resources of a specified type across your AWS environment
- **Schema Information**: Returns detailed CloudFormation schema for any resource to enable more effective operations
- **Natural Language Interface**: Transform infrastructure-as-code from static authoring to dynamic conversations
- **Partner Resource Support**: Works with both AWS-native and partner-defined resources
- **Template Generation**: Generates a template on created/existing resources for a [subset of resource types](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-supported-resources.html)

## Secure Workflow

For resource creation and updates, the server follows this secure workflow:

1. Check for AWS credentials and display account ID and region to the user
2. Generate a template
3. Run security scans against the template
4. If checks pass, attempt to create/update resource(s) with the AWS Cloud Control API. Will add default tags to the resource (if supported) to easily determine which are being managed by the MCP server
5. Validate that the resource(s) were created/updated successfully
6. Provide a summary of what was done
7. (Optional) create an IaC template that aligns to the resources it just created or updated

This workflow ensures that:

- Resources are validated before creation/modification
- Security checks are performed to prevent insecure configurations
- Users have the option to preserve their infrastructure as code
- Multiple IaC formats are supported for maximum flexibility

## Security Protections

The MCP server implements several critical security protections:

### Credential Awareness

- Always displays AWS account ID and region before any CREATE/UPDATE operation
- Ensures users are aware of which account will be affected by changes

### Deletion Safeguards

- Requires double confirmation for any resource deletion
- Prevents mass deletion of AWS infrastructure
- For cleanup operations, uses IaC Generator to create templates instead of direct deletion
- Provides safer alternatives with better control and rollback options

### Policy Restrictions

- Blocks creation of overly permissive IAM policies
- Prevents configurations with "AWS": "\*" as a principal
- Blocks "Effect": "Allow" combined with "Action": "_" and "Resource": "_"
- Declines requests for public access to sensitive resources
- Prevents disabling encryption for sensitive data

## Authentication

This MCP server requires authentication to an AWS account, as its primary intent is to be able to manage infrastructure. There are multiple options you have for authentication such as:

### AWS Profile

This can be set via the AWS CLI by running `aws configure` and following the instructions.

### Environment Variables

You can set environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION) by exporting them.

## Environment Variables

The MCP server supports several environment variables to control its behavior:

### AWS Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | *(see priority below)* | AWS region for operations |
| `AWS_PROFILE` | *(empty)* | AWS profile name to use for authentication |

**Region Selection Priority:**
1. `AWS_REGION` environment variable (if set)
2. Region from AWS profile configuration (if using profiles)
3. Region from `~/.aws/config` default profile
4. `us-east-1` (fallback when using environment variables without profile)
5. Boto3's default region resolution (for other cases)

**When to set AWS_REGION:**
- **To override region**: When you want to use a different region than the default
- **With environment variables**: When using `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` and don't want `us-east-1`
- **With profiles/SSO**: When you want to override the profile's configured region
- **Not needed**: When using AWS profiles/SSO and you want the profile's configured region, or when `us-east-1` is acceptable

### AWS Credential Chain

The server uses boto3's standard credential chain automatically:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS profile from `~/.aws/credentials` or `~/.aws/config`
3. IAM roles (EC2 instance, ECS task, EKS pod)
4. AWS SSO (if configured in profile)

**SSO Token Management**: When SSO tokens expire, the server provides clear instructions to refresh them with `aws sso login --profile your-profile`.

### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_TAGS` | `enabled` | Controls automatic resource tagging |
| `FASTMCP_LOG_LEVEL` | *(not set)* | Logging level (ERROR, WARN, INFO, DEBUG) |

### Default Tagging

When `DEFAULT_TAGS=enabled` (default), the server automatically adds these tags to supported resources:
- `MANAGED_BY`: `ccapi-mcp-server`
- `MCP_SERVER_SOURCE_CODE`: `https://github.com/awslabs/mcp/tree/main/src/ccapi-mcp-server`

To disable default tagging, set `DEFAULT_TAGS=disabled`.

### AWS Account Information Display

The server automatically displays AWS account information on startup:
- **AWS Profile**: The profile being used (if any)
- **AWS Account ID**: The AWS account ID
- **AWS Region**: The region where resources will be created
- **Read-only Mode**: Whether the server is in read-only mode

This ensures you always know which AWS account and region will be affected by operations.

## Installation

**Before installation, configure AWS credentials using one of these methods:**
- **AWS Profile**: Run `aws configure` and set `AWS_PROFILE` environment variable (region from profile used automatically)
- **Environment Variables**: Export `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (defaults to `us-east-1`, set `AWS_REGION` to override)
- **AWS SSO**: Configure SSO profile and set `AWS_PROFILE` (region from profile used automatically)
- **Instance Role**: Use EC2 instance role or ECS task role (automatic detection, may need `AWS_REGION`)

Ensure your IAM role or user has the necessary permissions (see [Security Considerations](#security-considerations)).

### Configuration

Configure the MCP server in your MCP client configuration (e.g., for Amazon Q Developer CLI, edit `~/.aws/amazonq/mcp.json`):

```json
{
  "mcpServers": {
    "awslabs.ccapi-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.ccapi-mcp-server@latest"],
      "env": {
        "AWS_PROFILE": "your-named-profile",
        "DEFAULT_TAGS": "enabled",
        "FASTMCP_LOG_LEVEL": "ERROR"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```
*Note: Uses the default region from your AWS profile. Add `"AWS_REGION": "us-west-2"` to override.*

**Alternative configurations:**

**Using Environment Variables for Credentials:**
```json
{
  "mcpServers": {
    "awslabs.ccapi-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.ccapi-mcp-server@latest"],
      "env": {
        "AWS_REGION": "us-west-2",
        "DEFAULT_TAGS": "enabled"
      }
    }
  }
}
```
*Note: Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are exported in your shell*

**Using AWS SSO:**
```json
{
  "mcpServers": {
    "awslabs.ccapi-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.ccapi-mcp-server@latest"],
      "env": {
        "AWS_PROFILE": "your-sso-profile"
      }
    }
  }
}
```
*Note: Run `aws sso login --profile your-sso-profile` before starting the MCP server*

**Read-Only Mode (Security Feature):**

To prevent the MCP server from performing any mutating actions (Create/Update/Delete), use the `--readonly` command-line flag. This is a security feature that cannot be bypassed via environment variables:

```json
{
  "mcpServers": {
    "awslabs.ccapi-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.ccapi-mcp-server@latest", "--readonly"],
      "env": {
        "AWS_PROFILE": "your-named-profile",
        "DEFAULT_TAGS": "enabled",
        "FASTMCP_LOG_LEVEL": "ERROR"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

or docker after a successful `docker build -t awslabs/ccapi-mcp-server .`:

```file
# fictitious `.env` file with AWS temporary credentials
AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_SESSION_TOKEN=AQoEXAMPLEH4aoAH0gNCAPy...truncated...zrkuWJOgQs8IZZaIv2BXIa2R4Olgk
```

```json
{
  "mcpServers": {
    "awslabs.ccapi-mcp-server": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "--interactive",
        "--env-file",
        "/full/path/to/file/above/.env",
        "awslabs/ccapi-mcp-server:latest",
        "--readonly" // Optional paramter if you would like to restrict the MCP to only read actions
      ],
      "env": {},
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

NOTE: Your credentials will need to be kept refreshed from your host

## Tools

### create_resource

Creates an AWS resource using the AWS Cloud Control API with a declarative approach.
**Example**: Create an S3 bucket with versioning and encryption enabled.

### get_resource

Gets details of a specific AWS resource using the AWS Cloud Control API.
**Example**: Get the configuration of an EC2 instance.

### update_resource

Updates an AWS resource using the AWS Cloud Control API with a declarative approach.
**Example**: Update an RDS instance's storage capacity.

### delete_resource

Deletes an AWS resource using the AWS Cloud Control API.
**Example**: Remove an unused NAT gateway.

### list_resources

Lists AWS resources of a specified type using AWS Cloud Control API.
**Example**: List all EC2 instances in a region.

### get_resource_schema_information

Get schema information for an AWS CloudFormation resource.
**Example**: Get the schema for AWS::S3::Bucket to understand all available properties.

### get_request_status

Get the status of a mutation that was initiated by create/update/delete resource.
**Example**: Give me the status of the last request I made.

### create_tempalte

Create a Cloudformation template from created or listed resources.
**Example**: Create a YAML template for those resources.

## Basic Usage

Examples of how to use the AWS Infrastructure as Code MCP Server:

- "Create a new S3 bucket with versioning and encryption enabled"
- "List all EC2 instances in the production environment"
- "Update the RDS instance to increase storage to 500GB"
- "Delete unused NAT gateways in VPC-123"
- "Set up a three-tier architecture with web, app, and database layers"
- "Create a disaster recovery environment in us-east-1"
- "Configure CloudWatch alarms for all production resources"
- "Implement cross-region replication for critical S3 buckets"
- "Show me the schema for AWS::Lambda::Function"
- "Create a template for all the resources we created and modified"

## Resource Type support

Resources which are supported by this MCP and the supported operations can be found here: https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html

## Security Considerations

When using this MCP server, you should consider:

- Ensuring proper IAM permissions are configured before use
- Use AWS CloudTrail for additional security monitoring
- Configure resource-specific permissions when possible instead of wildcard permissions
- Consider using resource tagging for better governance and cost management
- Review all changes made by the MCP server as part of your regular security reviews
- If you would like to restrict the MCP to readonly operations, specify --readonly True in the startup arguments for the MCP

### Required IAM Permissions

Ensure your AWS credentials have the following minimum permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudcontrol:ListResources",
        "cloudcontrol:GetResource",
        "cloudcontrol:CreateResource",
        "cloudcontrol:DeleteResource",
        "cloudcontrol:UpdateResource",
        "cloudformation:CreateGeneratedTemplate",
        "cloudformation:DescribeGeneratedTemplate",
        "cloudformation:GetGeneratedTemplate"
      ],
      "Resource": "*"
    }
  ]
}
```

## Future Enhancements

- **IaC Format Conversion**: Add support for converting CloudFormation templates to other IaC formats (Terraform HCL, CDK TypeScript, CDK Python) in the `create_template` tool

## Limitations

- Operations are limited to resources supported by AWS Cloud Control API and Iac Generator
- Performance depends on the underlying AWS services' response times
- Some complex resource relationships may require multiple operations
- This MCP server can only manage resources in the AWS regions where Cloud Control API and/or Iac Generator is available
- Resource modification operations may be limited by service-specific constraints
- Rate limiting may affect operations when managing many resources simultaneously
- Some resource types might not support all operations (create, read, update, delete)
- Generated templates are primarily intended for importing existing resources into a CloudFormation stack and may not always work for creating new resources (in another account or region)
- Template generation currently supports CloudFormation format only (JSON/YAML)
