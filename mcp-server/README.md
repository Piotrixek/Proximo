# Proximo MCP Server

Model Context Protocol (MCP) server for Proximo enabling AI agents to inspect running Windows processes, analyze loaded dynamic libraries, extract exported PE functions, rank proxy DLL candidates, and generate complete C++ and MASM proxy projects.

## Available Tools

- `list_processes`: List running processes with PID, executable path, memory usage, and optional name filtering.
- `get_process_details`: Get detailed information about a specific process by PID or process name.
- `list_process_modules`: Enumerate all loaded DLL modules inside a process, categorized by proxy suitability.
- `get_dll_exports`: Parse PE export tables on disk and extract function names, ordinals, and relative virtual addresses.
- `analyze_proxy_candidates`: Automatically analyze a target process (e.g. `game.exe`), extract exports, and score the best candidate DLLs for proxying.
- `generate_proxy_project`: Generate a complete, ready-to-compile C++ / MASM / CMake project with perfect 1:1 export forwarding.
- `build_proxy_project`: Compile a generated proxy project using CMake and the installed MSVC toolchain.
- `get_proxy_deployment_guide`: Step-by-step instructions on deploying the generated proxy DLL and original DLL in the target application directory.

## Installation & Setup

1. Install dependencies:
   ```bash
   cd mcp-server
   npm install
   ```

2. Run the MCP server directly:
   ```bash
   node index.js
   ```

## Configuration for MCP Clients

### Gemini / Antigravity IDE / Claude Desktop configuration (`claude_desktop_config.json` or `mcp_config.json`):

```json
{
  "mcpServers": {
    "proximo": {
      "command": "node",
      "args": [
        "c:/Users/User/OneDrive/Desktop/C O D I N G/Proximo/mcp-server/index.js"
      ]
    }
  }
}
```
