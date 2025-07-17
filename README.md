
# MCP Servers for Network Devices

# Setup
### System requirements

- Python 3.10 or higher installed.
- You must use the Python MCP SDK 1.2.0 or higher.
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
.venv\Scripts\activate

# Install dependencies
uv add mcp[cli] httpx
```

Running MCP server
```powershell
uv run {server}.py
```
## Linux/MacOS

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

```bash
# Create a new directory for our project
git clone {url}
cd {directory}

# Create virtual environment and activate it
uv venv
source .venv/bin/activate

# Install dependencies
uv add "mcp[cli]" httpx

# Create our server file
touch weather.py
```

Running MCP server
```bash
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
