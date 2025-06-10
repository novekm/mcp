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

## Prerequisites

- All prerequisites listed in the [Installation and Setup](https://github.com/awslabs/mcp#installation-and-setup) section within the awslabs/mcp README should be satisfied
- Valid AWS credentials
- Ensure your IAM role or user has the necessary permissions (see [Security Considerations](#security-considerations))

## Authentication

This MCP server requires authentication to an AWS account, as its primary intent is to be able to manage infrastructure. There are multiple options you have for authentication such as:

### SSO (Recommended)

We recommend using this MCP server with single-sign-on (SSO) to provide short-lived credentials that are automatically rotated. This would be using AWS IAM Identity Center (formerly known as AWS SSO). Beyond the security best practices, this MCP server also will attempt to automatically refresh these credentials if they expire. This is not possible for the other options. To configure sso, run the command `aws sso configure` and follow the steps in the wizard. To use the sso profile, run the command `aws sso login`

**NOTE:** If you have configured sso with `aws configure sso` and get an error that mentions a `sso_start_url` not being present, it is because you are not using the correct profile. When using the `aws configure sso`, it will walk you through setting up sso, including creating an AWS Profile. The error is occurring because you either didn't define a start url or start region when configuring sso, or you are not supplying the name of the one of the sso profiles you created. The command you should run is `aws sso login --profile YOUR-PROFILE-NAME` replacing `YOUR-PROFILE-NAME` with the name of the profile as it appears in your config file. You can see the values of this config file at `~/.aws/config` on macOS and Linux machines, or on Windows at `%UserProfile%\.aws\config` which usually expands to `C:\Users\username\.aws\config`.

Optionally, when running `aws configure sso` if you set the profile name as `default` running `aws sso login` will use that profile without you having to pass in the `--profile` flag. However, we highly recommend that you do not use a default AWS profile, especially if you are operating in a multi-account environment. This could allow accidental configuration changes within an incorrect AWS account. For that reason, we recommend using descriptive profile names when setting up sso, and passing in the `--profile` flag every time you need to sign in.

### AWS Profile

This can be set via the AWS CLI by running `aws configure` and following the instructions.

### Environment Variables

You can set environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION) by exporting them.

### Validating Authentication

To validate that you have valid AWS credentials you can run the command:

```sh
aws sts get-caller-identity
```

If you are using a profile (such as through sso) you can add the `--profile` flag to target it, replacing `YOUR-PROFILE-NAME` with the name of your profile:

```
aws sts get-caller-identity --profile YOUR-PROFILE-NAME
```

### Authentication Flow

This MCP server uses the AWS SDK for Python. The official AWS SDK credential provider chain is:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc.)
2. Shared credential file (~/.aws/credentials)
3. AWS SSO token cache
4. Web identity token from environment or config file
5. EC2/ECS instance profile credentials

By default, if no explicit value set, it will follow this default flow. This poses a challenge, because there could be a situation where you have valid credentials, but they are just further down the chain, after invalid credentials. This would prevent authentication from being able to happen successfully.

This MCP server allows for customization of this flow, allowing you to set the specific credential source you wish to use with the `AWS_CREDENTIAL_SOURCE` environment variable. Valid values for this are as follows:

- `AWS_PROFILE`: The name of the AWS profile you wish to use. This must be set if `AWS_CREDENTIAL_SOURCE` is set to anything other than `env` or `environment` unless you are using the default AWS profile. This is used by the MCP server for configuration, and automatic session refresh (if possible).
- `env` or `environment`: Attempts to use environment variables that a user has exported
- `profile`: Attempts to use the profile defined in the `AWS_PROFILE` environment variable. If this value is set, you must also set a value for the `AWS_PROFILE` environment variable.
- `sso`: Attempts to use the SSO token cache
- `instance` or `role`: Attempts to use an instance profile (for service, such as EC2 instance or a ECS/EKS container)

**Note:** There is also an `AWS_REGION` environment variable that can be set. If you do net set this, it will default to `us-east-1`.

## Installation

Here are some ways you can work with MCP across AWS, and we'll be adding support to more products including Amazon Q Developer CLI soon: (e.g. for Amazon Q Developer CLI MCP, `~/.aws/amazonq/mcp.json`):

### With SSO

Ensure you have run `aws sso configure` to configure sso, and `aws sso login` to login via SSO (which generates the necessary sso token and caches it).

```json
{
  "mcpServers": {
    "awslabs.ccapi-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.ccapi-mcp-server@latest"],
      "env": {
        "AWS_CREDENTIAL_SOURCE": "sso",
        "AWS_PROFILE": "your-profile-name"
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
    "awslabs.ccapi-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.ccapi-mcp-server@latest"],
      "env": {
        "AWS_CREDENTIAL_SOURCE": "profile",
        "AWS_PROFILE": "your-profile-name"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### With Exported Environment Variables

Ensure you have exported valid environment variables. You can check this by running `env | grep AWS_`

```json
{
  "mcpServers": {
    "awslabs.ccapi-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.ccapi-mcp-server@latest"],
      "env": {
        "AWS_CREDENTIAL_SOURCE": "env"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Default Resource Tagging

Default tags are enabled by default to help you easily identify which AWS resources in your account are being managed by the CloudFormation MCP server. When enabled, the following tags will be automatically added to all resources that support tagging:

- `MANAGED_BY`: CloudFormation MCP Server
- `MCP_SERVER_SOURCE_CODE`: https://github.com/awslabs/mcp/tree/main/src/ccapi-mcp-server

The tagging functionality is implemented in the `add_default_tags` function in `cloud_control_utils.py`, which checks if the resource type supports tagging and adds the default tags if enabled.

To disable automatic tagging, set `DEFAULT_TAGS` to `disabled`. **_HIGHLY recommended_** that if you disable default tags, you include your own descriptive tags so you can distinguish which resources this MCP server is managing versus other resources that may be in your AWS account(s).

```json
{
  "mcpServers": {
    "awslabs.ccapi-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.ccapi-mcp-server@latest"],
      "env": {
        "AWS_CREDENTIAL_SOURCE": "env",
        "DEFAULT_TAGS": "disabled"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```
