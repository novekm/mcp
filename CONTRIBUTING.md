# Contributing Guidelines

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary
information to effectively respond to your bug report or contribution.

## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

- A reproducible test case or series of steps
- The version of our code being used
- Any modifications you've made relevant to the bug
- Anything unusual about your environment or deployment

## Contributing via Pull Requests

Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the _main_ branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted. For instance, if you want to propose a new MCP Server, you would need to fist open a RFC issue.

The [Developer guide](DEVELOPER_GUIDE.md) provides the steps to set up your dev environment and make sure your code is ready before you submit your pull request.

GitHub provides additional document on [forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).

## Finding contributions to work on

Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the default GitHub issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any 'help wanted' issues is a great place to start.

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
opensource-codeofconduct@amazon.com with any additional questions or comments.

## Security issue notifications

If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.

## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.

# Local Development and Testing

Note: These instructions have only been validated on MacOS.

## Prerequisites

- Review [this guide on Model Context Protocol (MCP)](https://github.com/modelcontextprotocol/python-sdk?tab=readme-ov-file#what-is-mcp) in the python-sdk, starting with the **What is MCP** section. This is a very helpful guide that covers the core concepts such as Servers, Resources, Tools, Prompts, Context, and a variety of other helpful information, as well as how to use them with the python-sdk.
- Python `3.x.x` installed (e.g. `3.13.12`)
- MCP Host installed that supports MCP Clients and MCP Servers (e.g. Amazon Q Developer, Claude Desktop, Cursor, Cline, etc.)
- For some awslabs MCP servers, an AWS profile may also be necessary. You can run `aws configure` to set this up. See [these docs](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-files.html) for more information.

## Setup

1. Validate that you have Python `3.x.x` installed. It should output a version that is at least version 3 (e.g. `3.13.2`)

```sh
python3 --version
```

2. Install [uv](https://docs.astral.sh/uv/) from astral in whichever package manager you use (brew, pip3, etc.)

```sh
brew install uv
```

3. Validate that `uv` was successfully installed

```sh
uv --version
```

3. Clone the awslabs MCP repo (or fork it, then clone the fork) and navigate the root of the project

```sh
git clone https://github.com/awslabs/mcp.git
```

```sh
cd mcp
```

4. Change directory to the root directory of the mcp server you wish to work on and test locally. This directory will include a file named `pyproject.toml`:

```sh
cd src/<name of the MCP server folder (e.g. cfn-mcp-server)>
```

5. In the root directory for the specific MCP server (where the `pyproject.toml` file is located) set up a virtual environment using uv. This will create a `.venv` directory within the current working directory

```sh
uv venv
```

6. Activate the virtual environment and install all dependencies listed in `pyproject.toml`. This ensures our dependencies will be installed in the correct location and includes the `mpc-cli`, which is required to ensure we can run the mcp server locally for this python MCP server. Ensure you also install the dev dependencies.

```sh
source .venv/bin/activate
```

```sh
uv pip install -e .
```

```sh
uv pip install "commitizen>=4.2.2" "pre-commit>=4.1.0" "ruff>=0.9.7" "pyright>=1.1.398" "pytest>=8.0.0" "pytest-asyncio>=0.26.0" "pytest-cov>=4.1.0" "pytest-mock>=3.12.0"

```

7. **IMPORTANT**: Next, ensure MCP CLI was successfully installed in the correct location. This should be in the `.venv/bin/` directory within your current working directory. The following should return an absolute path to the `mcp` package directory that is within `.venv/bin/`

```sh
which mcp
```

Example:

```sh
/Users/novekm/Documents/Development/github-projects/mcp/src/cfn-mcp-server/.venv/bin/mcp
```

**NOTE:** If the command returns an absolute path that **does not** include the name of your current working directory (e.g. `cfn-mcp-server`) then you likely had another virtual environment open recently and installed `mcp` there. This absolute path is likely currently stored in your `PATH` environment variable. This is not actually an issue with the installation of `mcp`. If you use the file explorer in your IDE, you should see a directory named `mcp` within `.venv/.bin/`.

However, the issue is that if you were to delete that other `.venv` directory, you would encounter `command not found` errors since `mcp` would not be in the `PATH` it is trying to find it.

To resolve this, clear your shell's command cache and re-run `which mcp` and it should now show the correct PATH:

```sh
hash -r
```

```sh
which mcp
```

8.  Change directory into `/awslabs/<name of the mcp server (e.g. cfn_mcp_server)>` and run `pwd` to get the absolute path to that directory (or whatever subdirectory the `server.py` file is located in). Save this value, you will need it later

```sh
cd awslabs/<name of the mcp server (e.g. cfn_mcp_server)>
pwd
```

10. Run `ls`, you should see a number of python files and potentially subdirectories, but the key is to ensure you see the file named `server.py` - this is the core MCP server python script. The name can be anything, however for **awslabs**, all MCP servers follow a similar directory structure and naming convention.

11. Next, let's do a quick test of the MCP server. The following will start a run of the MCP server and should show you status information:

```sh
mcp dev server.py
```

You should see an output similar to the following. Enter `:q` to exit

```sh
Starting MCP inspector...
⚙️ Proxy server listening on port 6277
🔍 MCP Inspector is up and running at http://127.0.0.1:6274 🚀
```

```sh
:q
```

12. Next, we will try to configure out MCP Host. First, check where your package manager installed `uv`. This is important for the MCP Host configuration, as we will need to point to this correctly for local development and testing.

```sh
which uv
```

This will output the location where `uv` was installed to. This will differ depending on which package manager you used to install uv.

Example output for uv that was installed with Homebrew:

```sh
/opt/homebrew/bin/uv
```

13. In the MCP Host application that you wish to use that supports an MCP Clients and MCP Servers (Amazon Q CLI, Claude Desktop, Cursor, etc.), add the following to the MCP configuration file. It is typically named `mcp.json` (`claude_desktop_config.json` for Claude Desktop). For Amazon Q, on Mac/Linux, this is located at `~/.aws/amazonq/mcp.json`. Create the file if it doesn't exist, open it and paste in the following configuration, replacing the placeholder values where needed:

- `<server-name>`: Replace with any name you'd like to use for the server. This is just how it will appear in your MCP Host. It can be anything, but we recommend something descriptive like dev.awslabs.<the name of mcp server you are working on>. This is especially helpful if you are comparing two versions of the same MCP server - the public version hosted in the python package registry, and the local version on your filesystem.
- `<replace with output of 'which uv'>`: At described, replace with the output displayed after running the command `which uv`. This is especially important, as it tells your local machine how to resolve the PATH correctly to point to the location `uv` was installed to.

Use the descriptions in the placeholders to fill out the rest of the values.

```sh
{
  "mcpServers": {
    "<server-name>": {
      "command": "<replace with output of which uv>",
      "args": [
        "--directory",
        "<absolute path to GitHub repo you cloned>/src/<name-of-the-mcp-server>/awslabs/<name_of_the_mcp_server>",
        "run",
        "server.py"
      ],
      "env": {
        "PYTHONPATH": "<absolute path to GitHub repo you cloned>/src/<name-of-the-mcp-server>"
      }
    }
  }
}
```

Once completed, it should look similar to the following:

### Local reference to core-mcp-server (uv installed with Homebrew)

```sh
{
  "mcpServers": {
    "dev.awslabs.core-mcp-server": {
      "command": "/opt/homebrew/bin/uv",
      "args": [
        "--directory",
        "/Users/novekm/Documents/Development/github-projects/mcp/src/core-mcp-server/awslabs/core_mcp_server",
        "run",
        "server.py"
      ],
      "env": {
        "PYTHONPATH": "/Users/novekm/Documents/Development/github-projects/mcp/src/core-mcp-server"
      }
    }
  }
}
```

12. Open your terminal, and run `q chat` to start a chat session. This will start to attempt to initialize and load your MCP servers. **Note:** It may take a bit longer to load the MCP server for the first time. Subsequent loads of the same MCP servers should be quicker. You can check the status of the MCP server initialization and configuration by running `/mpc` within an active q chat session.

### Ex. First Load

```sh
❯ q chat
⚠ 0 of 1 mcp servers initialized. Servers still loading:
 - devawslabscore_mcp_server

    ⢠⣶⣶⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣿⣿⣶⣦⡀⠀
 ⠀⠀⠀⣾⡿⢻⣿⡆⠀⠀⠀⢀⣄⡄⢀⣠⣤⣤⡀⢀⣠⣤⣤⡀⠀⠀⢀⣠⣤⣤⣤⣄⠀⠀⢀⣤⣤⣤⣤⣤⣤⡀⠀⠀⣀⣤⣤⣤⣀⠀⠀⠀⢠⣤⡀⣀⣤⣤⣄⡀⠀⠀⠀⠀⠀⠀⢠⣿⣿⠋⠀⠀⠀⠙⣿⣿⡆
 ⠀⠀⣼⣿⠇⠀⣿⣿⡄⠀⠀⢸⣿⣿⠛⠉⠻⣿⣿⠛⠉⠛⣿⣿⠀⠀⠘⠛⠉⠉⠻⣿⣧⠀⠈⠛⠛⠛⣻⣿⡿⠀⢀⣾⣿⠛⠉⠻⣿⣷⡀⠀⢸⣿⡟⠛⠉⢻⣿⣷⠀⠀⠀⠀⠀⠀⣼⣿⡏⠀⠀⠀⠀⠀⢸⣿⣿
 ⠀⢰⣿⣿⣤⣤⣼⣿⣷⠀⠀⢸⣿⣿⠀⠀⠀⣿⣿⠀⠀⠀⣿⣿⠀⠀⢀⣴⣶⣶⣶⣿⣿⠀⠀⠀⣠⣾⡿⠋⠀⠀⢸⣿⣿⠀⠀⠀⣿⣿⡇⠀⢸⣿⡇⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⢹⣿⣇⠀⠀⠀⠀⠀⢸⣿⡿
 ⢀⣿⣿⠋⠉⠉⠉⢻⣿⣇⠀⢸⣿⣿⠀⠀⠀⣿⣿⠀⠀⠀⣿⣿⠀⠀⣿⣿⡀⠀⣠⣿⣿⠀⢀⣴⣿⣋⣀⣀⣀⡀⠘⣿⣿⣄⣀⣠⣿⣿⠃⠀⢸⣿⡇⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠈⢿⣿⣦⣀⣀⣀⣴⣿⡿⠃
 ⠚⠛⠋⠀⠀⠀⠀⠘⠛⠛⠀⠘⠛⠛⠀⠀⠀⠛⠛⠀⠀⠀⠛⠛⠀⠀⠙⠻⠿⠟⠋⠛⠛⠀⠘⠛⠛⠛⠛⠛⠛⠃⠀⠈⠛⠿⠿⠿⠛⠁⠀⠀⠘⠛⠃⠀⠀⠘⠛⠛⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠿⢿⣿⣿⣋⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⢿⡧

╭─────────────────────────────── Did you know? ────────────────────────────────╮
│                                                                              │
│         Use /model to select the model to use for this conversation          │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯

/help all commands  •  ctrl + j new lines  •  ctrl + s fuzzy search
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 You are chatting with claude-3.7-sonnet

> /mcp
devawslabscore_mcp_server
▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔
✓ devawslabscore_mcp_server loaded in 9.77 s
```

### Ex. Second Load

```sh
❯ q chat
✓ devawslabscore_mcp_server loaded in 0.36 s
✓ 1 of 1 mcp servers initialized.


    ⢠⣶⣶⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣿⣿⣶⣦⡀⠀
 ⠀⠀⠀⣾⡿⢻⣿⡆⠀⠀⠀⢀⣄⡄⢀⣠⣤⣤⡀⢀⣠⣤⣤⡀⠀⠀⢀⣠⣤⣤⣤⣄⠀⠀⢀⣤⣤⣤⣤⣤⣤⡀⠀⠀⣀⣤⣤⣤⣀⠀⠀⠀⢠⣤⡀⣀⣤⣤⣄⡀⠀⠀⠀⠀⠀⠀⢠⣿⣿⠋⠀⠀⠀⠙⣿⣿⡆
 ⠀⠀⣼⣿⠇⠀⣿⣿⡄⠀⠀⢸⣿⣿⠛⠉⠻⣿⣿⠛⠉⠛⣿⣿⠀⠀⠘⠛⠉⠉⠻⣿⣧⠀⠈⠛⠛⠛⣻⣿⡿⠀⢀⣾⣿⠛⠉⠻⣿⣷⡀⠀⢸⣿⡟⠛⠉⢻⣿⣷⠀⠀⠀⠀⠀⠀⣼⣿⡏⠀⠀⠀⠀⠀⢸⣿⣿
 ⠀⢰⣿⣿⣤⣤⣼⣿⣷⠀⠀⢸⣿⣿⠀⠀⠀⣿⣿⠀⠀⠀⣿⣿⠀⠀⢀⣴⣶⣶⣶⣿⣿⠀⠀⠀⣠⣾⡿⠋⠀⠀⢸⣿⣿⠀⠀⠀⣿⣿⡇⠀⢸⣿⡇⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⢹⣿⣇⠀⠀⠀⠀⠀⢸⣿⡿
 ⢀⣿⣿⠋⠉⠉⠉⢻⣿⣇⠀⢸⣿⣿⠀⠀⠀⣿⣿⠀⠀⠀⣿⣿⠀⠀⣿⣿⡀⠀⣠⣿⣿⠀⢀⣴⣿⣋⣀⣀⣀⡀⠘⣿⣿⣄⣀⣠⣿⣿⠃⠀⢸⣿⡇⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠈⢿⣿⣦⣀⣀⣀⣴⣿⡿⠃
 ⠚⠛⠋⠀⠀⠀⠀⠘⠛⠛⠀⠘⠛⠛⠀⠀⠀⠛⠛⠀⠀⠀⠛⠛⠀⠀⠙⠻⠿⠟⠋⠛⠛⠀⠘⠛⠛⠛⠛⠛⠛⠃⠀⠈⠛⠿⠿⠿⠛⠁⠀⠀⠘⠛⠃⠀⠀⠘⠛⠛⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠿⢿⣿⣿⣋⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⢿⡧

╭─────────────────────────────── Did you know? ────────────────────────────────╮
│                                                                              │
│      Set a default model by running q settings chat.defaultModel MODEL.      │
│                          Run /model to learn more.                           │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯

/help all commands  •  ctrl + j new lines  •  ctrl + s fuzzy search
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 You are chatting with claude-3.7-sonnet
```

From this point on, you can continue to make changes to the MCP server you wish to work on. Note that you must restart the session with your MCP Host for the changes to load. If using Q CLI, enter `/quit` to end the chat session, then `q chat` to start another one and reload the changes to the MCP server.
