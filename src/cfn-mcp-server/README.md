# CloudFormation MCP Server

Model Context Protocol (MCP) server that enables LLMs to directly create and manage over 1,100 AWS resources through natural language using AWS Cloud Control API and Iac Generator with Infrastructure as Code best practices.

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
3. Run security scans against the template with Checkov
4. If checks pass, attempt to create/update resource(s) with the AWS Cloud Control API
5. Validate that the resource(s) were created/updated successfully
6. Provide a summary of what was done, and ask if the user would want it to create a backup in IaC and provide the code. If the user agrees, it will ask them if they want the code in CloudFormation (JSON/YAML), Terraform, CDK (with language selection), or another format.

This workflow ensures that:

- Resources are validated before creation/modification
- Security checks are performed to prevent insecure configurations
- Users have the option to preserve their infrastructure as code
- Multiple IaC formats are supported for maximum flexibility

## Security Protections

The MCP server implements several critical security protections:

### Credential Awareness

- Always displays AWS account ID and region before any operation
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

## Prerequisites

1. Configure AWS credentials:
   - Via AWS CLI: `aws configure`
   - Or set environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION)
2. Ensure your IAM role or user has the necessary permissions (see [Security Considerations](#security-considerations))

## Authentication

The official AWS SDK credential provider chain is:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc.)
2. Shared credential file (~/.aws/credentials)
3. AWS SSO token cache
4. Web identity token from environment or config file
5. EC2/ECS instance profile credentials

By default, if no explicit value set, it will follow this default flow. This poses a challenge, because there could be a situation where you have valid credentials, but they are just further down the chain, after invalid credentials. This would prevent authentication from being able to happen successfully.

This MCP server allows for customization of this flow, allowing you to set the specific credential source you wish to use with the `AWS_CREDENTIAL_SOURCE` environment variable. Valid values for this are as follows:

- `env` or `environment`: Attempts to use environment variables that a user has exported
- `profile`: Attempts to use the profile defined in the `AWS_PROFILE` environment variable. If this value is set, you must also set a value for the `AWS_PROFILE` environment variable.
- `sso`: Attempts to use the SSO token cache
- `instance` or `role`: Attempts to use an instance profile (for service, such as EC2 instance or a ECS/EKS container)

If none of these are set, an error will be thrown instead of following the default credentials provider chain, for the reasons mentioned above.

**Note:** There is also an `AWS_REGION` environment variable that can be set. If you do net set this, it will default to `us-east-1`.

## Installation

Here are some ways you can work with MCP across AWS, and we'll be adding support to more products including Amazon Q Developer CLI soon: (e.g. for Amazon Q Developer CLI MCP, `~/.aws/amazonq/mcp.json`):

### With Exported Environment Variables

Ensure you have exported valid environment variables. You can check this by running `env | grep AWS_`

```json
{
  "mcpServers": {
    "awslabs.cfn-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.cfn-mcp-server@latest"],
      "env": {
        "AWS_CREDENTIAL_SOURCE": "env"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### With AWS Profile

Ensure your AWS Profile has been configured correctly. To configure an AWS Profile, you can either mainly edit the `config` file in `~/.aws` (Linux/Unix) or you can use the AWS CLI by running `aws configure`.

```json
{
  "mcpServers": {
    "awslabs.cfn-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.cfn-mcp-server@latest"],
      "env": {
        "AWS_CREDENTIAL_SOURCE": "profile",
        "AWS_PROFILE": "your-named-profile"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### With SSO

Ensure you have run `aws sso configure` to configure sso, and `aws sso login` to login via SSO (which generates the necessary sso token and caches it).

```json
{
  "mcpServers": {
    "awslabs.cfn-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.cfn-mcp-server@latest"],
      "env": {
        "AWS_CREDENTIAL_SOURCE": "sso"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Output Formatting

You can control how the LLM formats its responses by setting the `OUTPUT_FORMAT` environment variable:

```json
{
  "mcpServers": {
    "awslabs.cfn-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.cfn-mcp-server@latest"],
      "env": {
        "AWS_CREDENTIAL_SOURCE": "env",
        "OUTPUT_FORMAT": "emoji",
        "DEFAULT_TAGS": "enabled"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

Available output formats:

- `dynamic` (default): Adapts formatting based on content type
- `emoji`: Rich formatting with emojis and visual hierarchy
- `json`: Clean JSON formatting
- `yaml`: YAML formatting

### Default Resource Tagging

You can enable automatic tagging of resources by setting the `DEFAULT_TAGS` environment variable:

```json
{
  "mcpServers": {
    "awslabs.cfn-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.cfn-mcp-server@latest"],
      "env": {
        "AWS_CREDENTIAL_SOURCE": "env",
        "DEFAULT_TAGS": "enabled"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

Default tags are enabled by default to help you easily identify which resources are being managed by the MCP server in your AWS account. When enabled, the following tags will be automatically added to all resources that support tagging:
- `MANAGED_BY`: CloudFormation MCP Server
- `MCP_SERVER_SOURCE_CODE`: https://github.com/awslabs/mcp/tree/main/src/cfn-mcp-server

To disable automatic tagging, set `DEFAULT_TAGS` to `disabled`. ***HIGHLY recommended*** that if you disable default tags, you include your own descriptive tags so you can distinguish which resources this MCP server is managing versus other resources that may be in your AWS account(s).

### Read-Only Mode

If you would like to prevent the MCP from taking any mutating actions (i.e. Create/Update/Delete Resource), you can specify the readonly flag as demonstrated below:

```json
{
  "mcpServers": {
    "awslabs.cfn-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.cfn-mcp-server@latest", "--readonly"],
      "env": {
        "AWS_PROFILE": "your-named-profile"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

When running in read-only mode:
- The LLM will clearly inform users that the server is in read-only mode
- Create/Update/Delete operations on AWS resources are strictly prohibited
- The LLM cannot use `create_resource`, `update_resource`, or `delete_resource` tools
- Users can still list and view existing resources
- Users can still generate example code and run security checks
- The LLM will suggest alternatives like generating templates instead of direct resource creation

#### Sample Prompts to Test Read-Only Mode

1. **Attempt to create a resource**:
   ```
   Create an S3 bucket for me with versioning enabled.
   ```
   Expected response: The LLM should inform you it's in read-only mode and offer to generate example code instead.

2. **Request to view existing resources**:
   ```
   List all my S3 buckets in the current region.
   ```
   Expected response: The LLM should successfully list the buckets since this is a read operation.

3. **Request for example code**:
   ```
   Generate code for a secure S3 bucket with encryption and versioning.
   ```
   Expected response: The LLM should provide the example code since generating code is allowed in read-only mode.
```

or docker after a successful `docker build -t awslabs/cfn-mcp-server .`:

```file
# fictitious `.env` file with AWS temporary credentials
AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_SESSION_TOKEN=AQoEXAMPLEH4aoAH0gNCAPy...truncated...zrkuWJOgQs8IZZaIv2BXIa2R4Olgk
```

```json
{
  "mcpServers": {
    "awslabs.cfn-mcp-server": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "--interactive",
        "--env-file",
        "/full/path/to/file/above/.env",
        "awslabs/cfn-mcp-server:latest",
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

## Secure Workflow

This MCP server implements a secure workflow that separates code generation from resource creation/modification, allowing security checks to run in between:

1. **Generate Code**: Create resource definitions without deploying them
2. **Security Check**: Validate the generated code for security issues
3. **Create/Update Resource**: Only deploy resources after security validation

### Recommended Workflow (supplied to LLM by default)

For creating resources:

1. Use `get_aws_account_info` to display AWS account ID and region
2. Use `generate_resource_code` to create the resource definition
3. Use `run_checkov` to check for security issues
4. Use `create_resource` to create the resource if no issues are found

For updating resources:

1. Use `get_aws_account_info` to display AWS account ID and region
2. Use `generate_update_code` to prepare the update
3. Use `run_checkov` to check for security issues
4. Use `update_resource` to apply the changes if no issues are found

For deleting individual resources:

1. Use `get_aws_account_info` to display AWS account ID and region
2. Ask for explicit confirmation TWICE
3. Use `delete_resource` with the `confirmed` parameter set to `true`

For managing multiple resources or cleanup:

1. Use `get_aws_account_info` to display AWS account ID and region
2. Use `create_template` to generate a CloudFormation template of existing resources
3. Provide the template to the user for review and management as a CloudFormation stack

## Tools

### generate_resource_code

Generates code for an AWS resource without creating it, allowing for security checks.
**Example**: Generate code for an S3 bucket with versioning and encryption.

### create_resource

Creates an AWS resource using the AWS Cloud Control API after security checks.
**Example**: Create an S3 bucket with versioning and encryption enabled.

### generate_update_code

Generates update code for an AWS resource without applying changes, allowing for security checks.
**Example**: Generate code to update an RDS instance's storage capacity.

### update_resource

Updates an AWS resource using the AWS Cloud Control API after security checks.
**Example**: Update an RDS instance's storage capacity.

### delete_resource

Deletes an AWS resource using the AWS Cloud Control API (requires double confirmation).
**Example**: Remove an unused NAT gateway.

**Important**: This tool requires explicit confirmation twice and will display the AWS account ID and region before deletion. It will not allow mass deletion of resources - for cleaning up multiple resources, use create_template instead.

### run_checkov

Runs security and compliance checks on infrastructure code.
**Example**: Check S3 bucket configuration for security issues.

### get_resource

Gets details of a specific AWS resource using the AWS Cloud Control API.
**Example**: Get the configuration of an EC2 instance.

### list_resources

Lists AWS resources of a specified type using AWS Cloud Control API.
**Example**: List all EC2 instances in a region.

### get_resource_schema_information

Get schema information for an AWS CloudFormation resource.
**Example**: Get the schema for AWS::S3::Bucket to understand all available properties.

### get_resource_request_status

Get the status of a mutation that was initiated by create/update/delete resource.
**Example**: Give me the status of the last request I made.

### create_template

Create a CloudFormation template from created or listed resources, with optional conversion to other IaC formats.
**Example**: Create a YAML template for those resources.

This tool can:

- Generate CloudFormation templates in YAML or JSON format
- Convert CloudFormation templates to Terraform (HCL)
- Convert CloudFormation templates to AWS CDK (TypeScript/Python)
- Support other IaC formats upon request

After creating resources, the server will ask if you want to generate a template as a backup. You can choose from:

- CloudFormation (JSON/YAML)
- Terraform
- CDK (with language selection like TypeScript or Python)
- Other formats as they become available

**Preferred for Resource Management**: This is the recommended approach for managing multiple resources or cleaning up infrastructure. Instead of deleting resources individually, generate a template that can be reviewed and managed as a CloudFormation stack, providing better control and rollback options.

**Usage**: "Create a template for my S3 buckets and convert it to Terraform"

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

### Built-in Security Features

The MCP server includes several built-in security features:

- **Credential Awareness**: Always displays AWS account ID and region before operations
- **Double Confirmation**: Requires explicit confirmation twice for deletion operations
- **Mass Deletion Protection**: Prevents deletion of all resources in an account
- **Security Policy Enforcement**: Blocks creation of overly permissive IAM policies
- **Checkov Integration**: Automatically scans templates for security issues
- **IaC Generation**: Offers template generation for safer resource management

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

## Limitations

- Operations are limited to resources supported by AWS Cloud Control API and Iac Generator
- Performance depends on the underlying AWS services' response times
- Some complex resource relationships may require multiple operations
- This MCP server can only manage resources in the AWS regions where Cloud Control API and/or Iac Generator is available
- Resource modification operations may be limited by service-specific constraints
- Rate limiting may affect operations when managing many resources simultaneously
- Some resource types might not support all operations (create, read, update, delete)
- Generated templates are primarily intended for importing existing resources into a CloudFormation stack and may not always work for creating new resources (in another account or region)
