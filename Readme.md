The CytrixMCP (Management and Control Plane) is essential for enabling intelligent, 
autonomous control of the Cytrix platform through natural language. It allows users to 
integrate powerful AI models like ChatGPT, Claude, or Cursor directly with Cytrix, 
enabling them to launch scans, interpret results, and execute complex attack sequences 
using simple prompts. By serving as a communication bridge between AI agents and the 
Cytrix API, the MCP transforms traditional security testing into an automated, agentic process. 
This not only reduces manual effort and accelerates testing but also empowers users—technical 
and non-technical alike—to leverage cutting-edge AI to interact with and operate the platform 
as if they were speaking to a skilled human tester

-------------------------------------------------------
STEP 1: UV Installation -
    For windows, Open CMD as administrator and run

    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    
For Linux & Mac -

    curl -LsSf https://astral.sh/uv/install.sh | sh

OR

    wget -qO- https://astral.sh/uv/install.sh | sh

-------------------------------------------------------

STEP 2: Pip Install mcp -

    pip install mcp[cli]

-------------------------------------------------------
STEP 3: Insert to Claude -
1. Open PowerShell (on Windows) or your Terminal (on macOS/Linux) and change directory to where your CytrixMCP.py file is located.
2. Enter and execute the command below:


    uv run mcp install CytrixMCP.py

-------------------------------------------------------

STEP 4: Json Configuration -
1. Open Claude App
2. Go to file > Settings > Developers > Edit Config
3. Edit "claude_desktop_config" file

Windows:

    "CytrixMCP": {
          "command": "C:\\Users\\UserName\\.local\\bin\\uv.EXE",
          "args": [
            "run",
            "--with",
            "mcp[cli]",
            "mcp",
            "run",
            "to/your/path/CytrixMCP.py"
          ],
          "env": {
            "API_KEY": "xxxxxxxx-xxxx-xxxx-xxxxxxxx",
            "API_GATEWAY": "https://api.cytrix.io"
          }
        }
      }

Linux:

    "CytrixMCP": {
          "command": "uv",
          "args": [
            "run",
            "--with",
            "mcp[cli]",
            "mcp",
            "run",
            "to/your/path/CytrixMCP.py"
          ],
          "env": {
            "API_KEY": "xxxxxxxx-xxxx-xxxx-xxxxxxxx",
            "API_GATEWAY": "https://api.cytrix.io"
          }
        }
      }

-------------------------------------------------------

STEP 5: Restart Claude:

1. Open Task Manager and locate any running “Claude” processes.
2. Select the process and click End Task.
3. Relaunch the Claude application.

-------------------------------------------------------

STEP 6: Enjoy!