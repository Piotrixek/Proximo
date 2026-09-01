# Proximo MCP Server

A Model Context Protocol (MCP) server for **Proximo**, powered directly by its high-performance native **C++ Engine (`proximo_core`)** and the **LIEF** library.

This MCP server allows AI coding agents (such as Antigravity, Claude Desktop, Cursor) to inspect running Windows processes, parse Portable Executable (PE) headers, analyze loaded game modules, rank proxy DLL candidates, and generate fully compilable C++ / MASM proxy DLL projects automatically.

---

## Architecture Overview

Unlike typical script-based implementations, the Proximo MCP server uses a unified architecture where all analysis and generation logic is executed natively in C++:

- **Native C++ Engine (`proximo_core` / `proximo_cli`)**: Handles process snapshots (`CreateToolhelp32Snapshot`), elevation (`SeDebugPrivilege`), static PE analysis via **LIEF**, and complete CMake/MASM proxy code generation.
- **Ultra-Lightweight Bridge (`proximo_bridge.js`)**: A fast Stdio IPC interface between the MCP protocol and the native `proximo_cli` binary.
- **100% Shared Logic**: The exact same battle-tested C++ engine powers both the Proximo GUI and this MCP server.

---

## Available MCP Tools

### 1. `list_processes`
Lists all active processes running on Windows with PID, executable path, memory working set, and architecture (`x64` / `x86`).
- **Parameters:**
  - `filterQuery` *(optional, string)*: Substring filter matching process name, path, or PID.

### 2. `get_process_details`
Retrieves detailed metadata for a specific target process.
- **Parameters:**
  - `processIdentifierOrName` *(required, string | number)*: PID (e.g. `22052`) or executable name (e.g. `game.exe`).

### 3. `list_process_modules`
Enumerates all loaded DLL modules for a process. Uses LIEF static PE fallback to resolve imported and local directory DLLs even for processes with anti-cheat or memory protections. Categorizes modules into `good` (proxy candidates), `neutral`, and `system` (protected).
- **Parameters:**
  - `processIdentifierOrName` *(required, string | number)*: PID or executable name.

### 4. `get_dll_exports`
Parses PE export tables directly from disk using LIEF, extracting all exported function names, ordinals, relative virtual addresses (RVAs), and forwarder targets.
- **Parameters:**
  - `dllFilePath` *(required, string)*: Full or relative path to the DLL (e.g. `C:\Windows\System32\dxgi.dll`).

### 5. `analyze_proxy_candidates`
Performs automated end-to-end proxy suitability analysis on a target process. Scans all candidate modules, parses their exports via LIEF, and ranks them by suitability score (e.g. `dxgi.dll`, `dinput8.dll`, `version.dll`, `d3d11.dll`, `steam_api64.dll`).
- **Parameters:**
  - `processIdentifierOrName` *(required, string | number)*: PID or process executable name.

### 6. `generate_proxy_project`
Generates a complete, ready-to-compile proxy DLL project with CMake build system, `.def` export definitions with exact ordinals, C++ loader with custom payload hook, and MASM assembly trampolines (`.asm`) for zero-overhead 1:1 forwarding.
- **Parameters:**
  - `projectName` *(required, string)*: Name of the generated project (e.g. `dxgi_proxy`).
  - `outputDirectoryPath` *(required, string)*: Target folder path for generated files.
  - `targetModulePath` *(required, string)*: Path to the original target DLL.
  - `selectedFunctionNames` *(optional, array of strings)*: Specific subset of functions to forward.
  - `is64BitArchitecture` *(optional, boolean)*: Target architecture bitness.
  - `originalDllNameOverride` *(optional, string)*: Custom name for the renamed original DLL.
  - `enableDebugConsole` *(optional, boolean, default: true)*: Automatically attach debug console on injection.
  - `customPayloadCode` *(optional, string)*: Custom C++ code to execute upon DLL attach.

### 7. `build_proxy_project`
Compiles a generated proxy project using CMake and the installed MSVC / C++ toolchain into a release DLL.
- **Parameters:**
  - `projectDirectoryPath` *(required, string)*: Path to the directory containing `CMakeLists.txt`.
  - `buildConfiguration` *(optional, string, default: "Release")*: `Debug`, `Release`, `RelWithDebInfo`, `MinSizeRel`.

### 8. `get_proxy_deployment_guide`
Returns clear step-by-step instructions on deploying the compiled proxy DLL and original DLL into a game or application directory based on the Windows DLL search order.
- **Parameters:**
  - `targetDllName` *(optional, string)*: Name of the target DLL (e.g. `dxgi.dll`).
  - `gameExecutableName` *(optional, string)*: Name of the game executable (e.g. `game.exe`).

---

## Installation & Setup

1. **Build the Native C++ Engine:**
   ```bash
   cmake -B Build -S . -A x64
   cmake --build Build --config Release
   ```
   This compiles `Build\Release\proximo_cli.exe`.

2. **Install MCP Server Node Dependencies:**
   ```bash
   cd mcp-server
   npm install
   ```

3. **Test the Server:**
   ```bash
   node index.js
   ```

---

## Client Configuration

### Antigravity IDE / Claude Desktop (`mcp_config.json` / `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "proximo": {
      "command": "node",
      "args": [
        "C:\\Users\\User\\OneDrive\\Desktop\\C O D I N G\\Proximo\\mcp-server\\index.js"
      ]
    }
  }
}
```
