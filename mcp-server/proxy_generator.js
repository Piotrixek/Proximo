import fs from "fs";
import path from "path";
import { parsePeExports } from "./pe_parser.js";
import { exec } from "child_process";
import util from "util";

const executeCommandAsync = util.promisify(exec);

export function generateProxyProjectFiles({
    projectName,
    outputDirectoryPath,
    targetModulePath,
    selectedFunctionNames = null,
    is64BitArchitecture = true,
    originalDllNameOverride = null,
    enableDebugConsole = true,
    customPayloadCode = null
}) {
    try {
        if (!projectName || !outputDirectoryPath || !targetModulePath) {
            return {
                isSuccessful: false,
                errorMessage: "Missing required parameters: projectName, outputDirectoryPath, and targetModulePath are mandatory."
            };
        }

        const normalizedOutputDirectoryPath = path.resolve(outputDirectoryPath);
        const normalizedTargetModulePath = path.resolve(targetModulePath);

        if (!fs.existsSync(normalizedTargetModulePath)) {
            return {
                isSuccessful: false,
                errorMessage: "Target module DLL does not exist: " + normalizedTargetModulePath
            };
        }

        const peAnalysisResult = parsePeExports(normalizedTargetModulePath);
        if (!peAnalysisResult.isSuccessful || peAnalysisResult.exportedFunctions.length === 0) {
            return {
                isSuccessful: false,
                errorMessage: peAnalysisResult.errorMessage || "Target module has no exported functions to proxy."
            };
        }

        const effectiveIs64Bit = peAnalysisResult.is64BitArchitecture;
        const targetBaseFileName = path.basename(normalizedTargetModulePath, path.extname(normalizedTargetModulePath));
        const originalDllFileName = originalDllNameOverride || (targetBaseFileName + "_original.dll");

        let exportsToProxy = [];
        if (selectedFunctionNames && Array.isArray(selectedFunctionNames) && selectedFunctionNames.length > 0) {
            const selectedSet = new Set(selectedFunctionNames);
            exportsToProxy = peAnalysisResult.exportedFunctions.filter((exportItem) => selectedSet.has(exportItem.name));
            if (exportsToProxy.length === 0) {
                return {
                    isSuccessful: false,
                    errorMessage: "None of the selected function names matched exports in the target DLL."
                };
            }
        } else {
            exportsToProxy = peAnalysisResult.exportedFunctions;
        }

        if (!fs.existsSync(normalizedOutputDirectoryPath)) {
            fs.mkdirSync(normalizedOutputDirectoryPath, { recursive: true });
        }

        const cmakeListsContent = `cmake_minimum_required(VERSION 3.15)
project(${projectName} LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(${projectName} SHARED
    dllmain.cpp
    proxy.asm
)

if(MSVC)
    set_target_properties(${projectName} PROPERTIES
        LINK_FLAGS "/DEF:\\"\${CMAKE_CURRENT_SOURCE_DIR}/${projectName}.def\\""
    )
endif()
`;

        fs.writeFileSync(path.join(normalizedOutputDirectoryPath, "CMakeLists.txt"), cmakeListsContent, "utf8");

        const moduleDefinitionLines = [
            `LIBRARY ${projectName}`,
            `EXPORTS`
        ];

        for (const exportItem of exportsToProxy) {
            moduleDefinitionLines.push(`    ${exportItem.name} @${exportItem.ordinal}`);
        }

        fs.writeFileSync(
            path.join(normalizedOutputDirectoryPath, `${projectName}.def`),
            moduleDefinitionLines.join("\n") + "\n",
            "utf8"
        );

        const proxyHeaderLines = [
            `#pragma once`,
            `#include <windows.h>`,
            ``,
            `extern "C" {`
        ];

        for (const exportItem of exportsToProxy) {
            proxyHeaderLines.push(`    extern FARPROC pfn${exportItem.name};`);
        }

        proxyHeaderLines.push(`}`);
        proxyHeaderLines.push(``);

        fs.writeFileSync(
            path.join(normalizedOutputDirectoryPath, "proxy.h"),
            proxyHeaderLines.join("\n") + "\n",
            "utf8"
        );

        let payloadImplementation = "";
        if (customPayloadCode && typeof customPayloadCode === "string" && customPayloadCode.trim().length > 0) {
            payloadImplementation = customPayloadCode;
        } else if (enableDebugConsole) {
            payloadImplementation = `void ExecuteCustomPayload() {
    AllocConsole();
    FILE* streamPointer = nullptr;
    freopen_s(&streamPointer, "CONOUT$", "w", stdout);
    freopen_s(&streamPointer, "CONOUT$", "w", stderr);
    SetConsoleTitleA("Proximo Proxy - ${projectName}");
    printf("[Proximo] Proxy DLL attached successfully\\n");
    printf("[Proximo] Forwarding %zu exported functions to %s\\n", (size_t)${exportsToProxy.length}, originalDllName.c_str());
}`;
        } else {
            payloadImplementation = `void ExecuteCustomPayload() {
    MessageBoxA(NULL, "Proximo proxy DLL loaded successfully", "${projectName}", MB_OK | MB_ICONINFORMATION);
}`;
        }

        const dllMainLines = [
            `#include "proxy.h"`,
            `#include <string>`,
            `#include <windows.h>`,
            `#include <stdio.h>`,
            ``,
            `HMODULE originalModuleHandle = NULL;`,
            `const std::string originalDllName = "${originalDllFileName}";`,
            ``,
            `extern "C" {`
        ];

        for (const exportItem of exportsToProxy) {
            dllMainLines.push(`    FARPROC pfn${exportItem.name} = NULL;`);
        }

        dllMainLines.push(`}`);
        dllMainLines.push(``);
        dllMainLines.push(payloadImplementation);
        dllMainLines.push(``);
        dllMainLines.push(`void InitializeFunctionPointers(HMODULE moduleHandle) {`);

        for (const exportItem of exportsToProxy) {
            if (exportItem.isExportedByName) {
                dllMainLines.push(`    pfn${exportItem.name} = GetProcAddress(moduleHandle, "${exportItem.name}");`);
            } else {
                dllMainLines.push(`    pfn${exportItem.name} = GetProcAddress(moduleHandle, MAKEINTRESOURCEA(${exportItem.ordinal}));`);
            }
        }

        dllMainLines.push(`}`);
        dllMainLines.push(``);
        dllMainLines.push(`DWORD WINAPI PayloadThreadWorker(LPVOID parameter) {`);
        dllMainLines.push(`    ExecuteCustomPayload();`);
        dllMainLines.push(`    return 0;`);
        dllMainLines.push(`}`);
        dllMainLines.push(``);
        dllMainLines.push(`BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reasonForCall, LPVOID reservedPointer) {`);
        dllMainLines.push(`    switch (reasonForCall) {`);
        dllMainLines.push(`        case DLL_PROCESS_ATTACH:`);
        dllMainLines.push(`            DisableThreadLibraryCalls(moduleHandle);`);
        dllMainLines.push(`            originalModuleHandle = LoadLibraryA(originalDllName.c_str());`);
        dllMainLines.push(`            if (originalModuleHandle) {`);
        dllMainLines.push(`                InitializeFunctionPointers(originalModuleHandle);`);
        dllMainLines.push(`                CreateThread(NULL, 0, PayloadThreadWorker, NULL, 0, NULL);`);
        dllMainLines.push(`            } else {`);
        dllMainLines.push(`                char errorMessageBuffer[512];`);
        dllMainLines.push(`                sprintf_s(errorMessageBuffer, sizeof(errorMessageBuffer), "Failed to load original DLL: %s", originalDllName.c_str());`);
        dllMainLines.push(`                MessageBoxA(NULL, errorMessageBuffer, "Proximo Proxy Error", MB_OK | MB_ICONERROR);`);
        dllMainLines.push(`                return FALSE;`);
        dllMainLines.push(`            }`);
        dllMainLines.push(`            break;`);
        dllMainLines.push(`        case DLL_PROCESS_DETACH:`);
        dllMainLines.push(`            if (originalModuleHandle) {`);
        dllMainLines.push(`                FreeLibrary(originalModuleHandle);`);
        dllMainLines.push(`                originalModuleHandle = NULL;`);
        dllMainLines.push(`            }`);
        dllMainLines.push(`            break;`);
        dllMainLines.push(`    }`);
        dllMainLines.push(`    return TRUE;`);
        dllMainLines.push(`}`);

        fs.writeFileSync(
            path.join(normalizedOutputDirectoryPath, "dllmain.cpp"),
            dllMainLines.join("\n") + "\n",
            "utf8"
        );

        const proxyAsmLines = [];
        if (effectiveIs64Bit) {
            proxyAsmLines.push(`.CODE`);
            proxyAsmLines.push(``);
            for (const exportItem of exportsToProxy) {
                proxyAsmLines.push(`EXTERN pfn${exportItem.name}:QWORD`);
            }
            proxyAsmLines.push(``);
            for (const exportItem of exportsToProxy) {
                proxyAsmLines.push(`PUBLIC ${exportItem.name}`);
                proxyAsmLines.push(`${exportItem.name} PROC`);
                proxyAsmLines.push(`    jmp qword ptr [pfn${exportItem.name}]`);
                proxyAsmLines.push(`${exportItem.name} ENDP`);
                proxyAsmLines.push(``);
            }
            proxyAsmLines.push(`END`);
        } else {
            proxyAsmLines.push(`.MODEL FLAT, C`);
            proxyAsmLines.push(``);
            proxyAsmLines.push(`.CODE`);
            proxyAsmLines.push(``);
            for (const exportItem of exportsToProxy) {
                proxyAsmLines.push(`EXTERN pfn${exportItem.name}:DWORD`);
            }
            proxyAsmLines.push(``);
            for (const exportItem of exportsToProxy) {
                proxyAsmLines.push(`PUBLIC ${exportItem.name}`);
                proxyAsmLines.push(`${exportItem.name} PROC`);
                proxyAsmLines.push(`    jmp dword ptr [pfn${exportItem.name}]`);
                proxyAsmLines.push(`${exportItem.name} ENDP`);
                proxyAsmLines.push(``);
            }
            proxyAsmLines.push(`END`);
        }

        fs.writeFileSync(
            path.join(normalizedOutputDirectoryPath, "proxy.asm"),
            proxyAsmLines.join("\n") + "\n",
            "utf8"
        );

        const instructionsText = `# ${projectName} - Proxy DLL Project

Generated by Proximo MCP Server.

## Project Details
- Target Original Module: ${targetBaseFileName}.dll
- Renamed Original DLL: ${originalDllFileName}
- Architecture: ${effectiveIs64Bit ? "64-bit (x64)" : "32-bit (x86)"}
- Total Exported Functions Forwarded: ${exportsToProxy.length}

## How to Build
1. Open terminal in this folder:
   cd "${normalizedOutputDirectoryPath}"
2. Generate build files:
   cmake -B build -A ${effectiveIs64Bit ? "x64" : "Win32"}
3. Compile the DLL:
   cmake --build build --config Release

## How to Deploy
1. Find original "${targetBaseFileName}.dll" (either from Windows System directory or the target application folder).
2. Copy it to the application directory and rename it to "${originalDllFileName}".
3. Copy your compiled "${projectName}.dll" into the application directory and rename it to "${targetBaseFileName}.dll".
4. Launch the application!
`;

        fs.writeFileSync(
            path.join(normalizedOutputDirectoryPath, "DEPLOYMENT.md"),
            instructionsText,
            "utf8"
        );

        return {
            isSuccessful: true,
            projectName: projectName,
            outputDirectoryPath: normalizedOutputDirectoryPath,
            targetModulePath: normalizedTargetModulePath,
            originalDllFileName: originalDllFileName,
            is64BitArchitecture: effectiveIs64Bit,
            totalExportedFunctionsCount: exportsToProxy.length,
            generatedFiles: [
                path.join(normalizedOutputDirectoryPath, "CMakeLists.txt"),
                path.join(normalizedOutputDirectoryPath, `${projectName}.def`),
                path.join(normalizedOutputDirectoryPath, "proxy.h"),
                path.join(normalizedOutputDirectoryPath, "dllmain.cpp"),
                path.join(normalizedOutputDirectoryPath, "proxy.asm"),
                path.join(normalizedOutputDirectoryPath, "DEPLOYMENT.md")
            ]
        };
    } catch (error) {
        return {
            isSuccessful: false,
            errorMessage: "Failed to generate proxy project: " + error.message
        };
    }
}

export async function buildProxyProject(projectDirectoryPath, buildConfiguration = "Release") {
    try {
        const resolvedPath = path.resolve(projectDirectoryPath);
        if (!fs.existsSync(resolvedPath)) {
            return {
                isSuccessful: false,
                errorMessage: "Project directory does not exist: " + resolvedPath
            };
        }

        const buildFolderPath = path.join(resolvedPath, "build");
        const generateCommand = `cmake -B "${buildFolderPath}" -S "${resolvedPath}"`;
        const buildCommand = `cmake --build "${buildFolderPath}" --config ${buildConfiguration}`;

        const generateResult = await executeCommandAsync(generateCommand);
        const buildResult = await executeCommandAsync(buildCommand);

        return {
            isSuccessful: true,
            buildFolderPath: buildFolderPath,
            buildOutput: buildResult.stdout
        };
    } catch (error) {
        return {
            isSuccessful: false,
            errorMessage: "Build failed: " + error.message
        };
    }
}
