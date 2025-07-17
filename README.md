  

# MCP Servers for Network Devices

# Setup
### System requirements

- Python 3.10 or higher installed.
- You must use the Python MCP SDK 1.2.0 or higher.
- Choco

## Windows

Install the `uv` package manager.

```powershell

powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

```

Create Workspace

```powershell

git clone {url}

cd {directory}



# Create virtual environment and activate it

uv venv

.venv\Scripts\activate

  
# Sync dependencies

uv sync

```

  

Running MCP server

```powershell

uv run {server}.py

```
  

# Integrating MCP Server

  

```json

{

  "mcpServers": {

    "{Server}": {

      "command": "uv",

      "args": [

        "--directory",

        "/ABSOLUTE/PATH/TO/PARENT/FOLDER",

        "run",

        "{server}.py"

      ]

    }

  }

}

```