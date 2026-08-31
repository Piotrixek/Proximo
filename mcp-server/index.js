import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import path from "path";
import fs from "fs";

import { parsePeExports } from "./pe_parser.js";
import {
    enumerateRunningProcesses,
    findProcessByIdentifierOrName,
    enumerateProcessModules,
    analyzeProxyCandidatesForProcess
} from "./process_manager.js";
import {
    generateProxyProjectFiles,
    buildProxyProject
} from "./proxy_generator.js";

const serverInstance = new McpServer({
    name: "proximo-mcp-server",
    version: "1.0.0"
});

serverInstance.tool(
    "list_processes",
    "List running processes on the system with their PID, process name, window title, memory usage, and executable path.",
    {
        filterQuery: z.string().optional().describe("Optional search filter to match process name, window title, PID, or executable path")
    },
    async (toolArguments) => {
        const queryFilter = toolArguments.filterQuery || "";
        const processResult = await enumerateRunningProcesses(queryFilter);

        if (!processResult.isSuccessful) {
            return {
                isError: true,
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        status: "error",
                        message: processResult.errorMessage
                    }, null, 2)
                }]
            };
        }

        return {
            content: [{
                type: "text",
                text: JSON.stringify({
                    status: "success",
                    totalProcessesFound: processResult.totalFoundCount,
                    processes: processResult.processes
                }, null, 2)
            }]
        };
    }
);

serverInstance.tool(
    "get_process_details",
    "Get detailed information about a specific running process by PID or process name, including memory, architecture, and executable path.",
    {
        processIdentifierOrName: z.union([z.string(), z.number()]).describe("Process identifier (PID) or process executable name (e.g. game.exe or 1234)")
    },
    async (toolArguments) => {
        const lookupResult = await findProcessByIdentifierOrName(toolArguments.processIdentifierOrName);

        if (!lookupResult.isSuccessful) {
            return {
                isError: true,
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        status: "error",
                        message: lookupResult.errorMessage
                    }, null, 2)
                }]
            };
        }

        return {
            content: [{
                type: "text",
                text: JSON.stringify({
                    status: "success",
                    process: lookupResult.process
                }, null, 2)
            }]
        };
    }
);

serverInstance.tool(
    "list_process_modules",
    "List all loaded DLL modules inside a target process, categorized by proxy suitability (recommended proxy DLLs, local game DLLs, system protected DLLs).",
    {
        processIdentifierOrName: z.union([z.string(), z.number()]).describe("Process identifier (PID) or process executable name (e.g. game.exe or 1234)")
    },
    async (toolArguments) => {
        const modulesResult = await enumerateProcessModules(toolArguments.processIdentifierOrName);

        if (!modulesResult.isSuccessful) {
            return {
                isError: true,
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        status: "error",
                        message: modulesResult.errorMessage
                    }, null, 2)
                }]
            };
        }

        return {
            content: [{
                type: "text",
                text: JSON.stringify({
                    status: "success",
                    targetProcess: modulesResult.process,
                    totalModulesCount: modulesResult.totalModulesCount,
                    modules: modulesResult.modules
                }, null, 2)
            }]
        };
    }
);

serverInstance.tool(
    "get_dll_exports",
    "Parse PE headers of any DLL on disk and extract all exported functions with names, ordinals, RVAs, and forwarders.",
    {
        dllFilePath: z.string().describe("Absolute or relative file path to the target DLL file (e.g. C:\\Windows\\System32\\dinput8.dll)")
    },
    async (toolArguments) => {
        const resolvedPath = path.resolve(toolArguments.dllFilePath);
        const exportResult = parsePeExports(resolvedPath);

        if (!exportResult.isSuccessful) {
            return {
                isError: true,
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        status: "error",
                        message: exportResult.errorMessage,
                        filePath: resolvedPath
                    }, null, 2)
                }]
            };
        }

        return {
            content: [{
                type: "text",
                text: JSON.stringify({
                    status: "success",
                    filePath: exportResult.filePath,
                    fileName: exportResult.fileName,
                    architecture: exportResult.architecture,
                    is64BitArchitecture: exportResult.is64BitArchitecture,
                    totalExportsCount: exportResult.totalExportsCount,
                    exportedFunctions: exportResult.exportedFunctions
                }, null, 2)
            }]
        };
    }
);

serverInstance.tool(
    "analyze_proxy_candidates",
    "Inspect a running process, analyze all loaded DLLs, extract exports, and rank the best DLL proxy candidates (e.g. dinput8.dll, dxgi.dll, version.dll) with score and rationale.",
    {
        processIdentifierOrName: z.union([z.string(), z.number()]).describe("Process identifier (PID) or process executable name (e.g. game.exe or 1234)")
    },
    async (toolArguments) => {
        const analysisResult = await analyzeProxyCandidatesForProcess(toolArguments.processIdentifierOrName);

        if (!analysisResult.isSuccessful) {
            return {
                isError: true,
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        status: "error",
                        message: analysisResult.errorMessage
                    }, null, 2)
                }]
            };
        }

        return {
            content: [{
                type: "text",
                text: JSON.stringify({
                    status: "success",
                    targetProcess: analysisResult.targetProcess,
                    bestRecommendation: analysisResult.bestRecommendation,
                    totalCandidatesFound: analysisResult.totalCandidatesFound,
                    candidates: analysisResult.candidates
                }, null, 2)
            }]
        };
    }
);

serverInstance.tool(
    "generate_proxy_project",
    "Generate a complete, compilable C++ / MASM / CMake proxy project with perfect 1:1 export forwarding for any target DLL.",
    {
        projectName: z.string().describe("Name of the generated proxy project (e.g. MyGameProxy or dinput8_proxy)"),
        outputDirectoryPath: z.string().describe("Target folder path where project files will be created"),
        targetModulePath: z.string().describe("Path to the original DLL to be proxied (e.g. C:\\Windows\\System32\\dinput8.dll or a game DLL)"),
        selectedFunctionNames: z.array(z.string()).optional().describe("Optional subset of function names to proxy. If omitted, all exports are included."),
        is64BitArchitecture: z.boolean().optional().describe("Whether the target architecture is 64-bit. Auto-detected from DLL if omitted."),
        originalDllNameOverride: z.string().optional().describe("Custom filename for the renamed original DLL (defaults to <originalName>_original.dll)"),
        enableDebugConsole: z.boolean().optional().describe("Whether to automatically spawn a debug console on proxy attach (defaults to true)"),
        customPayloadCode: z.string().optional().describe("Custom C++ code to execute inside ExecuteCustomPayload() upon process injection")
    },
    async (toolArguments) => {
        const generationResult = generateProxyProjectFiles({
            projectName: toolArguments.projectName,
            outputDirectoryPath: toolArguments.outputDirectoryPath,
            targetModulePath: toolArguments.targetModulePath,
            selectedFunctionNames: toolArguments.selectedFunctionNames,
            is64BitArchitecture: toolArguments.is64BitArchitecture,
            originalDllNameOverride: toolArguments.originalDllNameOverride,
            enableDebugConsole: toolArguments.enableDebugConsole !== undefined ? toolArguments.enableDebugConsole : true,
            customPayloadCode: toolArguments.customPayloadCode
        });

        if (!generationResult.isSuccessful) {
            return {
                isError: true,
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        status: "error",
                        message: generationResult.errorMessage
                    }, null, 2)
                }]
            };
        }

        return {
            content: [{
                type: "text",
                text: JSON.stringify({
                    status: "success",
                    projectName: generationResult.projectName,
                    outputDirectoryPath: generationResult.outputDirectoryPath,
                    targetModulePath: generationResult.targetModulePath,
                    originalDllFileName: generationResult.originalDllFileName,
                    is64BitArchitecture: generationResult.is64BitArchitecture,
                    totalExportedFunctionsCount: generationResult.totalExportedFunctionsCount,
                    generatedFiles: generationResult.generatedFiles,
                    buildInstructions: `To build: cd "${generationResult.outputDirectoryPath}" && cmake -B build -A ${generationResult.is64BitArchitecture ? "x64" : "Win32"} && cmake --build build --config Release`
                }, null, 2)
            }]
        };
    }
);

serverInstance.tool(
    "build_proxy_project",
    "Compile a generated proxy project using CMake and the installed MSVC / C++ compiler toolchain.",
    {
        projectDirectoryPath: z.string().describe("Path to the directory containing CMakeLists.txt"),
        buildConfiguration: z.enum(["Debug", "Release", "RelWithDebInfo", "MinSizeRel"]).optional().describe("Build configuration type (defaults to Release)")
    },
    async (toolArguments) => {
        const configuration = toolArguments.buildConfiguration || "Release";
        const buildResult = await buildProxyProject(toolArguments.projectDirectoryPath, configuration);

        if (!buildResult.isSuccessful) {
            return {
                isError: true,
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        status: "error",
                        message: buildResult.errorMessage
                    }, null, 2)
                }]
            };
        }

        return {
            content: [{
                type: "text",
                text: JSON.stringify({
                    status: "success",
                    buildFolderPath: buildResult.buildFolderPath,
                    buildOutput: buildResult.buildOutput
                }, null, 2)
            }]
        };
    }
);

serverInstance.tool(
    "get_proxy_deployment_guide",
    "Get step-by-step instructions on deploying a compiled proxy DLL into an application directory.",
    {
        targetDllName: z.string().optional().describe("Name of the DLL being proxied (e.g. dinput8.dll)"),
        gameExecutableName: z.string().optional().describe("Name of the game or target application executable (e.g. game.exe)")
    },
    async (toolArguments) => {
        const dllName = toolArguments.targetDllName || "dinput8.dll";
        const baseDllName = path.basename(dllName, path.extname(dllName));
        const originalRenamedDllName = `${baseDllName}_original.dll`;
        const executableName = toolArguments.gameExecutableName || "game.exe";

        const guideText = `
# DLL Proxy Deployment Guide for ${dllName}

## Concept: Windows DLL Search Order
When ${executableName} starts, Windows searches for imported DLLs in this priority order:
1. Application directory (where ${executableName} is located)
2. Windows System directories (C:\\Windows\\System32 or C:\\Windows\\SysWOW64)
3. Windows directory (C:\\Windows)
4. Directories listed in the PATH environment variable

By placing our custom "${dllName}" directly into the application folder alongside ${executableName}, Windows loads our proxy DLL instead of the system DLL.

## Step-by-Step Instructions

### Step 1: Copy and Rename the Original DLL
- For 64-bit processes: Locate "${dllName}" in "C:\\Windows\\System32\\" (or from the game folder if it's a local DLL).
- For 32-bit processes: Locate "${dllName}" in "C:\\Windows\\SysWOW64\\".
- Copy "${dllName}" into the same folder as "${executableName}".
- Rename this copy to "${originalRenamedDllName}".

### Step 2: Place Your Proxy DLL
- Take your compiled proxy DLL.
- Rename it to "${dllName}".
- Place it into the same folder as "${executableName}".

### Step 3: Verify the Directory Structure
Your target directory should contain:
- ${executableName}
- ${dllName} (your compiled proxy DLL)
- ${originalRenamedDllName} (the original legitimate DLL)

### Step 4: Run
Launch ${executableName}. The proxy DLL will load first, establish 1:1 forwarders to ${originalRenamedDllName}, initialize your custom payload/debug console, and pass all original function calls seamlessly without crashing.
`;

        return {
            content: [{
                type: "text",
                text: guideText
            }]
        };
    }
);

async function startServer() {
    const transportInstance = new StdioServerTransport();
    await serverInstance.connect(transportInstance);
}

startServer().catch((error) => {
    process.stderr.write("Fatal MCP server error: " + error.message + "\n");
    process.exit(1);
});
