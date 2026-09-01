#include <ShlObj.h>
#include <Windows.h>
#include <atlbase.h>
#include <gdiplus.h>
#include <objidl.h>
#include <psapi.h>
#include <shellapi.h>
#include <tchar.h>
#include <tlhelp32.h>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include "dx_setup.h"
#include "ui_style.h"
#include "window_setup.h"

#include "font.h"
#include "icons.h"
#include "ultralight_controller.h"
#include <algorithm>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <io.h>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "json.hpp"
#include "menu.h"
#include "proximo_core.h"
#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>

using json = nlohmann::json;

std::unique_ptr<UltralightController> g_ultralight_controller;

void ExecuteScriptSafely(std::string javascriptCode)
{
    if (g_ultralight_controller)
    {
        g_ultralight_controller->evalScript(javascriptCode);
    }
}


void CopyTextToClipboard(const ultralight::JSObject &currentObject, const ultralight::JSArgs &functionArguments)
{
    if (functionArguments.size() < 1 || !functionArguments[0].IsString())
    {
        std::cout << " CopyTextToClipboard called with invalid arguments." << std::endl;
        return;
    }

    std::string textToCopy = ultralight::String(functionArguments[0].ToString()).utf8().data();

    if (!OpenClipboard(NULL))
    {
        std::cout << " Cannot open the Clipboard." << std::endl;
        return;
    }

    EmptyClipboard();
    HGLOBAL memoryHandle = GlobalAlloc(GMEM_MOVEABLE, textToCopy.size() + 1);
    if (!memoryHandle)
    {
        CloseClipboard();
        std::cout << " Cannot allocate memory for clipboard." << std::endl;
        return;
    }

    LPSTR destinationBuffer = (LPSTR)GlobalLock(memoryHandle);
    if (destinationBuffer)
    {
        strcpy_s(destinationBuffer, textToCopy.size() + 1, textToCopy.c_str());
        GlobalUnlock(memoryHandle);
        SetClipboardData(CF_TEXT, memoryHandle);
    }
    else
    {
        GlobalFree(memoryHandle);
    }

    CloseClipboard();
    std::cout << "Successfully copied " << textToCopy.size() << " bytes to clipboard." << std::endl;
}

void FetchRunningProcesses(const ultralight::JSObject &currentObject, const ultralight::JSArgs &functionArguments)
{
    json processListResult = GetRunningProcesses();
    json processListJsonArray = json::array();
    if (processListResult.contains("processes"))
    {
        for (const auto &processItem : processListResult["processes"])
        {
            json simpleObject;
            simpleObject["pid"] = processItem["processIdentifier"];
            simpleObject["name"] = processItem["processName"];
            processListJsonArray.push_back(simpleObject);
        }
    }
    ExecuteScriptSafely("populateProcessList(" + processListJsonArray.dump() + ");");
}

void FetchProcessModules(const ultralight::JSObject &currentObject, const ultralight::JSArgs &functionArguments)
{
    if (functionArguments.size() < 1 || !functionArguments[0].IsNumber())
    {
        ExecuteScriptSafely("populateModules({ modules: [] });");
        return;
    }

    DWORD targetProcessId = static_cast<DWORD>(functionArguments[0].ToNumber());
    json modulesResult = GetProcessModules(targetProcessId);
    ExecuteScriptSafely("populateModules(" + modulesResult.dump() + ");");
}

std::string ExtractExportsAsJson(std::string &filePath)
{
    json exportResult = GetDllExports(filePath);
    if (!exportResult["isSuccessful"].get<bool>() || !exportResult.contains("exportedFunctions"))
    {
        return "";
    }
    std::stringstream jsonStream;
    bool isFirstFunction = true;
    for (const auto &functionItem : exportResult["exportedFunctions"])
    {
        if (!isFirstFunction)
        {
            jsonStream << ",";
        }
        jsonStream << functionItem.dump();
        isFirstFunction = false;
    }
    return jsonStream.str();
}

void FetchExportedFunctions(const ultralight::JSObject &currentObject, const ultralight::JSArgs &functionArguments)
{
    if (functionArguments.size() < 1 || !functionArguments[0].IsString())
    {
        ExecuteScriptSafely("populateFunctions([]);");
        return;
    }
    std::string filePath = ultralight::String(functionArguments[0].ToString()).utf8().data();
    json exportResult = GetDllExports(filePath);
    if (exportResult["isSuccessful"].get<bool>() && exportResult.contains("exportedFunctions"))
    {
        ExecuteScriptSafely("populateFunctions(" + exportResult["exportedFunctions"].dump() + ");");
    }
    else
    {
        ExecuteScriptSafely("populateFunctions([]);");
    }
}

void FetchExportsForMultipleModules(const ultralight::JSObject &currentObject,
                                    const ultralight::JSArgs &functionArguments)
{
    if (functionArguments.size() < 1 || !functionArguments[0].IsArray())
    {
        ExecuteScriptSafely("populateReportData([]);");
        return;
    }

    ultralight::JSArray modulePathsArray = functionArguments[0].ToArray();
    json combinedExportList = json::array();

    for (size_t index = 0; index < modulePathsArray.length(); ++index)
    {
        std::string filePath = ultralight::String(modulePathsArray[index].ToString()).utf8().data();
        json exportResult = GetDllExports(filePath);
        if (exportResult["isSuccessful"].get<bool>() && exportResult.contains("exportedFunctions"))
        {
            for (const auto &functionItem : exportResult["exportedFunctions"])
            {
                combinedExportList.push_back(functionItem);
            }
        }
    }

    ExecuteScriptSafely("populateReportData(" + combinedExportList.dump() + ");");
}

void PromptUserForOutputFolder(const ultralight::JSObject &currentObject, const ultralight::JSArgs &functionArguments)
{
    HRESULT result = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(result))
    {
        CComPtr<IFileOpenDialog> fileOpenDialog;
        result = fileOpenDialog.CoCreateInstance(__uuidof(FileOpenDialog));
        if (SUCCEEDED(result))
        {
            fileOpenDialog->SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
            result = fileOpenDialog->Show(NULL);
            if (SUCCEEDED(result))
            {
                CComPtr<IShellItem> selectedItem;
                result = fileOpenDialog->GetResult(&selectedItem);
                if (SUCCEEDED(result))
                {
                    PWSTR folderPathString;
                    result = selectedItem->GetDisplayName(SIGDN_FILESYSPATH, &folderPathString);
                    if (SUCCEEDED(result))
                    {
                        std::string parsedPath = ConvertWideStringToUtf8(folderPathString);
                        size_t currentPosition = 0;
                        while ((currentPosition = parsedPath.find("\\", currentPosition)) != std::string::npos)
                        {
                            parsedPath.replace(currentPosition, 1, "\\\\");
                            currentPosition += 2;
                        }
                        ExecuteScriptSafely("setOutputDirectory('" + parsedPath + "');");
                        CoTaskMemFree(folderPathString);
                    }
                }
            }
        }
        CoUninitialize();
    }
}

void CreateProxyProject(const ultralight::JSObject &currentObject, const ultralight::JSArgs &functionArguments)
{
    ExecuteScriptSafely("updateStatusMessage('Starting project generation...', 'cog', 'text-accent', 10);");

    if (functionArguments.size() < 1 || !functionArguments[0].IsString())
    {
        ExecuteScriptSafely("updateStatusMessage('Error: Invalid args for generation.', 'bug', 'text-red-400', 0);");
        return;
    }
    std::string jsonOptionsString = ultralight::String(functionArguments[0].ToString()).utf8().data();

    try
    {
        json parsedOptions = json::parse(jsonOptionsString);
        json generationResult = GenerateProxyProject(parsedOptions);
        if (generationResult["isSuccessful"].get<bool>())
        {
            ExecuteScriptSafely("updateStatusMessage('Project generated successfully!', 'party-popper', 'text-success', 100);");
        }
        else
        {
            std::string errorMessage = generationResult.value("errorMessage", "Unknown error");
            ExecuteScriptSafely("updateStatusMessage('Error: " + errorMessage + "', 'file-x', 'text-red-400', 0);");
        }
    }
    catch (const std::exception &exceptionDetails)
    {
        ExecuteScriptSafely("updateStatusMessage('Error: " + std::string(exceptionDetails.what()) + "', 'file-x', 'text-red-400', 0);");
    }
}

void TerminateApplication(const ultralight::JSObject &currentObject, const ultralight::JSArgs &functionArguments)
{
    PostQuitMessage(0);
}

void SpawnDebugConsole()
{
    if (AllocConsole())
    {
        FILE *consoleOutputPointer;
        freopen_s(&consoleOutputPointer, "CONOUT$", "w", stdout);
        freopen_s(&consoleOutputPointer, "CONOUT$", "w", stderr);
        SetConsoleTitle("Proximo Debug Console");
        std::cout.clear();
        std::wcout.clear();
        std::cerr.clear();
        std::wcerr.clear();
        std::cout << "heyo! debug console is on" << std::endl;
    }
}

int main(int, char **)
{
    SpawnDebugConsole();
    EnableDebugPrivilege();
    LIEF::logging::disable();

    HINSTANCE applicationInstance = GetModuleHandle(NULL);
    const TCHAR *windowClassName = _T("ImGuiAppClass");
    HWND mainWindowHandle = InitializeHostWindow(applicationInstance, windowClassName);
    if (!mainWindowHandle)
    {
        return 1;
    }

    if (!InitializeDirect3D(mainWindowHandle))
    {
        ShutdownDirect3D();
        ::DestroyWindow(mainWindowHandle);
        DestroyHostWindow(applicationInstance, windowClassName);
        return 1;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

    io.IniFilename = nullptr;
    io.LogFilename = nullptr;

    ImFontConfig primaryFontConfiguration;
    primaryFontConfiguration.FontDataOwnedByAtlas = false;
    io.Fonts->AddFontFromMemoryTTF((void *)my_Font, sizeof(my_Font), 16.0f, &primaryFontConfiguration);

    static const ImWchar iconCharacterRanges[] = {0xf000, 0xf3ff, 0};
    ImFontConfig iconFontConfiguration;
    iconFontConfiguration.MergeMode = true;
    iconFontConfiguration.PixelSnapH = true;
    iconFontConfiguration.OversampleH = 3;
    iconFontConfiguration.OversampleV = 3;
    iconFontConfiguration.EllipsisChar = 0xf141;
    io.Fonts->AddFontFromMemoryCompressedTTF(font_awesome_data, font_awesome_size, 18.5f, &iconFontConfiguration,
                                             iconCharacterRanges);

    ApplyCommandMenuStyle();

    ImGuiStyle &guiStyle = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        guiStyle.WindowRounding = 0.0f;
        guiStyle.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    ImGui_ImplWin32_Init(mainWindowHandle);
    ImGui_ImplDX11_Init(GetDirect3DDevice(), GetDirect3DDeviceContext());

    try
    {
        g_ultralight_controller =
            std::make_unique<UltralightController>(GetDirect3DDevice(), GetDirect3DDeviceContext());
    }
    catch (const std::exception &exceptionDetails)
    {
        std::string errorMessage = "An exception occurred during Ultralight initialization:\n\n";
        errorMessage += exceptionDetails.what();
        errorMessage += "\n\nThis usually means the 'resources' folder is missing from the executable's directory.";
        MessageBoxA(NULL, errorMessage.c_str(), "Ultralight Initialization Failed", MB_OK | MB_ICONERROR);
        return 1;
    }

    if (!g_ultralight_controller->IsRendererValid())
    {
        MessageBox(NULL,
                   _T("Failed to initialize Ultralight Renderer!\n\nMake sure the 'resources' and '.dll' files from ")
                   _T("the SDK are in the same directory as your .exe."),
                   _T("Ultralight Error"), MB_OK | MB_ICONERROR);
        return 1;
    }

    g_ultralight_controller->AddCallback("fetchRunningProcesses", &FetchRunningProcesses);
    g_ultralight_controller->AddCallback("fetchProcessModules", &FetchProcessModules);
    g_ultralight_controller->AddCallback("fetchExportedFunctions", &FetchExportedFunctions);
    g_ultralight_controller->AddCallback("fetchExportsForMultipleModules", &FetchExportsForMultipleModules);
    g_ultralight_controller->AddCallback("promptUserForOutputFolder", &PromptUserForOutputFolder);
    g_ultralight_controller->AddCallback("createProxyProject", &CreateProxyProject);
    g_ultralight_controller->AddCallback("terminateApplication", &TerminateApplication);
    g_ultralight_controller->AddCallback("copyTextToClipboard", &CopyTextToClipboard);

    std::string htmlContentText = R"HTML_PART1(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy DLL Generator (Proximo)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #121212;
            color: #E0E0E0;
            overflow: hidden;
        }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1E1E1E; }
        ::-webkit-scrollbar-thumb { background: #4A4A4A; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #5A5A5A; }
        
        .bg-primary { background-color: #121212; }
        .bg-secondary { background-color: #1E1E1E; }
        .text-primary { color: #E0E0E0; }
        .text-accent { color: #00BFFF; }
        .border-accent { border-color: #00BFFF; }
        .bg-accent { background-color: #00BFFF; }
        .bg-success { background-color: #50FA7B; }
        .text-success { color: #50FA7B; }
        .text-red-400 { color: #FF5555; }
        .text-green-400 { color: #4ADE80; }

        .custom-select, .custom-input {
            background-color: #2a2a2a;
            border: 1px solid #4a4a4a;
            color: #E0E0E0;
        }
        .custom-select:focus, .custom-input:focus {
            outline: none;
            border-color: #00BFFF;
            box-shadow: 0 0 0 2px rgba(0, 191, 255, 0.5);
        }
        .data-grid-header { background-color: #2a2a2a; }
        .data-grid-row:hover { background-color: #282828; }
        .data-grid-row-selected {
            background-color: rgba(0, 191, 255, 0.1);
            border-left: 3px solid #00BFFF;
        }
        
        #debug-panel {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(0, 0, 0, 0.9);
            z-index: 1000;
            display: none;
        }
        
        .debug-content {
            background-color: #1a1a1a;
            border: 1px solid #4a4a4a;
            max-height: 90vh;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.4;
        }
    </style>
</head>
)HTML_PART1";

    htmlContentText += R"HTML_PART2(
<body class="bg-primary text-primary antialiased">
    <div id="debug-panel" class="flex items-center justify-center p-4">
        <div class="debug-content w-full max-w-4xl p-6 rounded-lg">
            <div class="flex justify-between items-center mb-4">
                <h2 class="text-xl font-bold text-accent">JavaScript Debug Log</h2>
                <button id="close-debug-btn" class="text-primary/50 hover:text-accent">
                    <i data-lucide="x" class="w-6 h-6"></i>
                </button>
            </div>
            <div id="debug-content" class="text-green-400 whitespace-pre-wrap"></div>
        </div>
    </div>

    <div class="flex h-screen max-h-screen relative">
        <div id="close-btn" class="absolute top-4 right-4 text-primary/50 hover:text-accent cursor-pointer z-50">
            <i data-lucide="x" class="w-6 h-6"></i>
        </div>
        
        <div id="debug-btn" class="absolute top-4 right-16 text-primary/50 hover:text-accent cursor-pointer z-50" title="Show JS Debug Info">
            <i data-lucide="bug" class="w-6 h-6"></i>
        </div>

        <div class="w-1/3 max-w-sm flex flex-col bg-secondary p-6 space-y-6 overflow-y-auto">
            <div class="flex-shrink-0">
                <h1 class="text-2xl font-bold text-primary">Proximo</h1>
                <div class="h-0.5 w-16 bg-accent mt-2"></div>
            </div>

            <div class="space-y-2">
                <div class="flex items-center justify-between">
                    <label for="process-select" class="text-sm font-semibold text-primary/80">1. Select Process</label>
                    <span id="process-count-badge" class="text-xs text-primary/50 font-mono">0 procs</span>
                </div>
                <div class="relative">
                    <i data-lucide="search" class="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-primary/40"></i>
                    <input type="text" id="process-search" placeholder="Search process by name or PID..." class="custom-input w-full p-2 pl-8 rounded-md text-sm">
                </div>
                <div class="flex items-center space-x-2">
                    <div class="relative flex-grow">
                        <select id="process-select" class="custom-select w-full p-2 rounded-md appearance-none">
                            <option value="">Loading processes...</option>
                        </select>
                        <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-primary/50">
                            <i data-lucide="chevron-down" class="w-4 h-4"></i>
                        </div>
                    </div>
                    <button id="refresh-procs-btn" class="p-2 bg-[#3a3a3a] hover:bg-[#4a4a4a] rounded-md" title="Refresh Processes">
                        <i data-lucide="refresh-cw" class="w-4 h-4"></i>
                    </button>
                </div>
            </div>

            <div class="space-y-2 flex-grow flex flex-col min-h-0">
                <label class="text-sm font-semibold text-primary/80">2. Select Target DLL</label>
                <div id="dll-list-container" class="bg-[#2a2a2a] border border-[#4a4a4a] rounded-md p-3 flex-grow overflow-y-auto">
                    <p class="text-primary/50 text-center py-4">Select a process to see its DLLs.</p>
                </div>
            </div>

            <div class="space-y-4 flex-shrink-0">
                <h3 class="text-sm font-semibold text-primary/80">3. Generation</h3>
                <div class="space-y-2">
                    <label for="project-name" class="text-xs font-medium">Project Name:</label>
                    <input type="text" id="project-name" class="custom-input w-full p-2 rounded-md text-sm" placeholder="e.g., MyProxyProject">
                </div>
                <div class="space-y-2">
                    <label for="output-dir" class="text-xs font-medium">Output Directory:</label>
                    <div class="flex">
                        <input type="text" id="output-dir" class="custom-input w-full p-2 rounded-l-md text-sm" placeholder="C:\Projects\">
                        <button id="browse-dir-btn" class="bg-[#3a3a3a] hover:bg-[#4a4a4a] p-2 rounded-r-md border-y border-r border-[#4a4a4a]">
                            <i data-lucide="folder-open" class="w-4 h-4"></i>
                        </button>
                    </div>
                </div>
                <button id="generate-btn" class="w-full bg-success/80 hover:bg-success text-black font-bold py-3 rounded-md transition-colors duration-200 flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed" disabled>
                    <i data-lucide="play" class="w-5 h-5"></i>
                    <span>Generate Project</span>
                </button>
            </div>
        </div>

        <div class="w-2/3 flex-grow flex flex-col p-6">
            <div class="flex-shrink-0">
                 <div class="flex items-center justify-between">
                      <h2 class="text-xl font-semibold">Functions Overview</h2>
                      <div class="flex items-center space-x-2">
                          <button id="generate-report-btn" class="p-2 bg-[#3a3a3a] hover:bg-[#4a4a4a] rounded-md text-primary/80 hover:text-accent" title="Generate & Copy Report">
                               <i data-lucide="clipboard-list" class="w-4 h-4"></i>
                          </button>
                          <button id="refresh-funcs-btn" class="p-2 bg-[#3a3a3a] hover:bg-[#4a4a4a] rounded-md text-primary/80 hover:text-accent" title="Refresh Functions">
                               <i data-lucide="refresh-cw" class="w-4 h-4"></i>
                          </button>
                      </div>
                 </div>
                <div class="relative mt-4">
                    <i data-lucide="search" class="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-primary/40"></i>
                    <input type="text" id="function-search" placeholder="Filter by function or DLL name..." class="custom-input w-full p-3 pl-10 rounded-md">
                </div>
            </div>

            <div class="mt-4 flex-grow overflow-y-auto">
                <table class="w-full text-left text-sm">
                    <thead class="sticky top-0">
                        <tr class="data-grid-header text-primary/80">
                            <th class="p-3 w-12"><input type="checkbox" id="select-all-funcs" class="h-4 w-4 rounded bg-[#2a2a2a] border-[#4a4a4a] text-accent focus:ring-accent"></th>
                            <th class="p-3">Function Name</th>
                            <th class="p-3">Module Name</th>
                            <th class="p-3">Type</th>
                            <th class="p-3">Parameters</th>
                        </tr>
                    </thead>
                    <tbody id="function-table-body">
                        <tr class="data-grid-row">
                            <td colspan="5" class="text-center p-16 text-primary/50">
                                <i data-lucide="list-x" class="w-12 h-12 mx-auto mb-2"></i>
                                <p>No process selected</p>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="flex-shrink-0 mt-4 h-10 flex items-center justify-between bg-secondary p-3 rounded-md">
                <div class="flex items-center space-x-2">
                    <span id="status-icon"></span>
                    <span id="status-text" class="text-xs font-medium">Ready</span>
                </div>
                <div class="w-1/3 bg-[#2a2a2a] rounded-full h-1.5">
                    <div id="progress-bar" class="bg-accent h-1.5 rounded-full" style="width: 0%"></div>
                </div>
            </div>
        </div>
    </div>
)HTML_PART2";

    htmlContentText += R"HTML_PART3(
    <script>
        const processDropdown = document.getElementById('process-select');
        const processSearchInput = document.getElementById('process-search');
        const processCountBadge = document.getElementById('process-count-badge');
        const refreshProcessesButton = document.getElementById('refresh-procs-btn');
        const moduleListContainer = document.getElementById('dll-list-container');
        const functionTableBodyElement = document.getElementById('function-table-body');
        const searchInput = document.getElementById('function-search');
        const selectAllFunctionsCheckbox = document.getElementById('select-all-funcs');
        const statusTextElement = document.getElementById('status-text');
        const statusIconElement = document.getElementById('status-icon');
        const progressBarElement = document.getElementById('progress-bar');
        const generateProjectButton = document.getElementById('generate-btn');
        const closeAppButton = document.getElementById('close-btn');
        const browseDirectoryButton = document.getElementById('browse-dir-btn');
        const outputDirectoryInput = document.getElementById('output-dir');
        const projectNameInput = document.getElementById('project-name');
        const refreshFunctionsButton = document.getElementById('refresh-funcs-btn');
        const createReportButton = document.getElementById('generate-report-btn');
        const showDebugButton = document.getElementById('debug-btn');
        const debugPanelContainer = document.getElementById('debug-panel');
        const debugContentText = document.getElementById('debug-content');
        const hideDebugButton = document.getElementById('close-debug-btn');

        let allRunningProcesses = [];
        let activeFunctionsList = [];
        let reportFunctionsList = [];
        let activeModulePath = '';
        let isTargetProcess32Bit = false;
        let javascriptDebugLog = "=== JAVASCRIPT DEBUG LOG ===\n\n";

        function appendToDebugLog(logMessage) {
            const timeStamp = new Date().toLocaleTimeString();
            javascriptDebugLog += `[${timeStamp}] ${logMessage}\n`;
            debugContentText.textContent = javascriptDebugLog;
        }

        function displayDebugPanel() {
            debugPanelContainer.style.display = 'flex';
            lucide.createIcons();
        }

        function hideDebugPanel() {
            debugPanelContainer.style.display = 'none';
        }

        function filterProcessList() {
            const searchTerm = processSearchInput ? processSearchInput.value.trim().toLowerCase() : '';
            const currentlySelectedPid = processDropdown.value;

            const filteredProcesses = allRunningProcesses.filter(processInfo => {
                if (!searchTerm) return true;
                const matchesName = processInfo.name.toLowerCase().includes(searchTerm);
                const matchesPid = String(processInfo.pid).includes(searchTerm);
                return matchesName || matchesPid;
            });

            if (processCountBadge) {
                if (searchTerm) {
                    processCountBadge.textContent = `${filteredProcesses.length}/${allRunningProcesses.length}`;
                } else {
                    processCountBadge.textContent = `${allRunningProcesses.length} procs`;
                }
            }

            processDropdown.innerHTML = '';

            if (filteredProcesses.length === 0) {
                const emptyOption = document.createElement('option');
                emptyOption.value = '';
                emptyOption.textContent = 'No matching processes found';
                processDropdown.appendChild(emptyOption);
                return;
            }

            const defaultOption = document.createElement('option');
            defaultOption.value = '';
            defaultOption.textContent = searchTerm 
                ? `Select process (${filteredProcesses.length} matches)...` 
                : 'Select a running process...';
            processDropdown.appendChild(defaultOption);

            let hasRestoredSelection = false;
            filteredProcesses.forEach(processInfo => {
                const optionElement = document.createElement('option');
                optionElement.value = processInfo.pid;
                optionElement.textContent = `${processInfo.name} (PID: ${processInfo.pid})`;
                if (String(processInfo.pid) === String(currentlySelectedPid)) {
                    optionElement.selected = true;
                    hasRestoredSelection = true;
                }
                processDropdown.appendChild(optionElement);
            });
        }

        function populateProcessList(runningProcesses) {
            appendToDebugLog(`populateProcessList called with ${runningProcesses.length} processes`);
            allRunningProcesses = runningProcesses;
            filterProcessList();
            updateStatusMessage('Ready. Select a process.', 'list', 'text-primary/80');
        }

        function populateModules(moduleData) {
        appendToDebugLog(`populateModules called with ${moduleData.modules.length} modules for a ${moduleData.is32BitProcess ? 'Wow64 (32-bit)' : '64-bit'} process.`);
        isTargetProcess32Bit = moduleData.is32BitProcess;
        const processModules = moduleData.modules;

            if (!processModules || processModules.length === 0) {
                moduleListContainer.innerHTML = `<p class="text-primary/50 text-center py-4">No DLLs found for this process.</p>`;
                return;
            }
			
			 moduleListContainer.innerHTML = processModules.map(moduleInfo => {
            const escapedModulePath = moduleInfo.path.replace(/"/g, '&quot;');
            const escapedModuleName = moduleInfo.name.replace(/"/g, '&quot;');
            
            let categoryLabelClass = '';
            let isCheckboxDisabled = false;
            switch(moduleInfo.category) {
                case 'system':
                    categoryLabelClass = 'text-red-400';
                    isCheckboxDisabled = true;
                    break;
                case 'good':
                    categoryLabelClass = 'text-green-400';
                    break;
                case 'neutral':
                default:
                    categoryLabelClass = '';
                    break;
            }
            const disabledAttribute = isCheckboxDisabled ? 'disabled' : '';
            
            return `
            <div class="flex items-center space-x-2 p-1.5 rounded hover:bg-[#3a3a3a]">
                <input type="checkbox" 
                        data-dll-name="${escapedModuleName}" 
                        data-dll-path="${escapedModulePath}" 
                        class="dll-checkbox h-4 w-4 rounded bg-[#2a2a2a] border-[#4a4a4a] text-accent focus:ring-accent" 
                        ${moduleInfo.selected ? 'checked' : ''} ${disabledAttribute}>
                <label class="text-sm ${categoryLabelClass}">${escapedModuleName}</label>
            </div>`;
        }).join('');
        
        requestFunctionsForActiveModule();
    }

        function populateFunctions(exportedFunctions) {
            appendToDebugLog(`populateFunctions called with ${exportedFunctions.length} functions`);
            activeFunctionsList = exportedFunctions;
            renderFunctionsTable();
            evaluateGenerationReadiness();
            
            if (exportedFunctions.length > 0) {
                updateStatusMessage(`Analysis complete. Found ${exportedFunctions.length} functions.`, 'check-circle', 'text-success');
                setTimeout(() => updateStatusMessage('Ready', '', 'text-primary/80', 0), 4000);
            } else if (document.querySelectorAll('.dll-checkbox:checked').length > 0) {
                updateStatusMessage('Analysis complete. No exported functions found.', 'search-x', 'text-primary/80');
            }
        }
        
        function populateReportData(gatheredFunctions) {
            appendToDebugLog(`Received data for report with ${gatheredFunctions.length} total functions.`);
            reportFunctionsList = gatheredFunctions;
            formatAndCopyFunctionsReport();
        }
        
        function formatAndCopyFunctionsReport() {
            if (reportFunctionsList.length === 0) {
                updateStatusMessage('No functions found in selected DLLs to report.', 'alert-circle', 'text-primary/80');
                setTimeout(() => updateStatusMessage('Ready', '', 'text-primary/80'), 3000);
                return;
            }

            const organizedModules = reportFunctionsList.reduce((accumulator, functionData) => {
                if (!accumulator[functionData.module]) {
                    accumulator[functionData.module] = [];
                }
                accumulator[functionData.module].push(functionData);
                return accumulator;
            }, {});

            let reportTextContent = `Proximo DLL & Function Report\nGenerated on: ${new Date().toLocaleString()}\n\n`;

            for (const moduleName in organizedModules) {
                reportTextContent += `--- DLL: ${moduleName} ---\n`;
                
                const moduleFunctionsList = organizedModules[moduleName];
                const functionsToDisplay = moduleFunctionsList.slice(0, 10);
                
                functionsToDisplay.forEach(functionData => {
                    reportTextContent += `- Function: ${(functionData.name || '').padEnd(40)} | Type: ${(functionData.type || '').padEnd(8)} | Params: ${functionData.parameters}\n`;
                });
                
                if (moduleFunctionsList.length > 10) {
                    reportTextContent += `...and ${moduleFunctionsList.length - 10} more functions.\n`;
                }
                reportTextContent += '\n';
            }

            window.copyTextToClipboard(reportTextContent);
            appendToDebugLog('Report passed to C++ for copying.');
            updateStatusMessage('Report copied to clipboard!', 'copy', 'text-success');
            setTimeout(() => updateStatusMessage('Ready', '', 'text-primary/80'), 3000);
        }

        function triggerReportGeneration() {
            appendToDebugLog('Generate report button clicked');
            
            const validCheckboxes = document.querySelectorAll('.dll-checkbox:not([disabled])');
            if (validCheckboxes.length === 0) {
                updateStatusMessage('No proxyable DLLs found to report on.', 'alert-circle', 'text-red-400');
                setTimeout(() => updateStatusMessage('Ready', '', 'text-primary/80'), 3000);
                return;
            }
            
            const viableModulePaths = Array.from(validCheckboxes)
                                              .map(checkbox => checkbox.getAttribute('data-dll-path'));

            if (viableModulePaths.length > 0) {
                updateStatusMessage(`Analyzing ${viableModulePaths.length} DLLs for report...`, 'loader-2 animate-spin', 'text-accent');
                window.fetchExportsForMultipleModules(viableModulePaths);
            }
        }

        function setOutputDirectory(folderPath) {
            appendToDebugLog(`setOutputDirectory called with path: ${folderPath}`);
            outputDirectoryInput.value = folderPath;
            evaluateGenerationReadiness();
        }

)HTML_PART3";

    htmlContentText += R"HTML_PART4(
        function updateStatusMessage(statusMessage, iconIdentifier = '', colorClassName = 'text-primary/80', progressValue = 0) {
            statusTextElement.textContent = statusMessage;
            statusTextElement.className = `text-xs font-medium ${colorClassName}`;
            statusIconElement.innerHTML = iconIdentifier ? `<i data-lucide="${iconIdentifier}" class="w-4 h-4"></i>` : '';
            if (iconIdentifier) lucide.createIcons();
            progressBarElement.style.width = `${progressValue}%`;
        }
        
        function requestFunctionsForActiveModule() {
			appendToDebugLog("=== requestFunctionsForActiveModule CALLED ===");
			
			const selectedModuleCheckbox = document.querySelector('.dll-checkbox:checked');
			
			if (selectedModuleCheckbox) {
				const activeModuleLocation = selectedModuleCheckbox.getAttribute('data-dll-path');
				const activeModuleName = selectedModuleCheckbox.getAttribute('data-dll-name');
                activeModulePath = activeModuleLocation;
				
				appendToDebugLog(`Found selected DLL: "${activeModuleName}" with path: "${activeModuleLocation}"`);

				if (activeModuleLocation && activeModuleLocation !== 'null' && activeModuleLocation.length > 0) {
					appendToDebugLog(`Calling C++ with string argument: "${activeModuleLocation}"`);
					updateStatusMessage(`Analyzing ${activeModuleName}...`, 'loader-2 animate-spin', 'text-accent', 50);
					
					window.fetchExportedFunctions(activeModuleLocation); 
					appendToDebugLog("Call to C++ completed.");
				} else {
					appendToDebugLog("ERROR: Selected DLL path is invalid.");
                    activeModulePath = '';
					updateStatusMessage('Error: Selected DLL has no path data.', 'alert-circle', 'text-red-400');
					populateFunctions([]);
				}
			} else {
				appendToDebugLog("No DLL is selected.");
                activeModulePath = '';
				updateStatusMessage('Ready', '', 'text-primary/80');
				populateFunctions([]);
			}
			appendToDebugLog("=== requestFunctionsForActiveModule FINISHED ===\n");
		}


        function renderFunctionsTable() {
            const selectedModuleNames = Array.from(document.querySelectorAll('.dll-checkbox:checked')).map(checkbox => checkbox.dataset.dllName);
            const currentSearchTerm = searchInput.value.toLowerCase();
            
            const filteredFunctions = activeFunctionsList.filter(functionData => 
                selectedModuleNames.includes(functionData.module) &&
                (functionData.name.toLowerCase().includes(currentSearchTerm) || functionData.module.toLowerCase().includes(currentSearchTerm))
            );

            if (filteredFunctions.length === 0) {
                if (selectedModuleNames.length > 0) {
                     functionTableBodyElement.innerHTML = `<tr class="data-grid-row"><td colspan="5" class="text-center p-16 text-primary/50"><i data-lucide="search-x" class="w-12 h-12 mx-auto mb-2"></i><p>No matching functions found for the selected DLL.</p></td></tr>`;
                } else {
                    functionTableBodyElement.innerHTML = `<tr class="data-grid-row"><td colspan="5" class="text-center p-16 text-primary/50"><i data-lucide="list-x" class="w-12 h-12 mx-auto mb-2"></i><p>Select a DLL to see functions.</p></td></tr>`;
                }
                lucide.createIcons();
                return;
            }

            functionTableBodyElement.innerHTML = filteredFunctions.map(functionData => `
                <tr class="data-grid-row border-b border-transparent" data-func-name="${functionData.name}" data-dll-name="${functionData.module}">
                    <td class="p-3"><input type="checkbox" class="func-checkbox h-4 w-4 rounded bg-[#2a2a2a] border-[#4a4a4a] text-accent focus:ring-accent" checked></td>
                    <td class="p-3 font-medium">${functionData.name}</td>
                    <td class="p-3 text-primary/70">${functionData.module}</td>
                    <td class="p-3">
                        <span class="px-2 py-1 text-xs rounded-full ${functionData.type === 'Export' ? 'bg-blue-900/50 text-blue-300' : 'bg-purple-900/50 text-purple-300'}">
                            ${functionData.type}
                        </span>
                    </td>
                    <td class="p-3 text-primary/50 font-mono text-xs">${functionData.parameters}</td>
                </tr>
            `).join('');
            
            functionTableBodyElement.querySelectorAll('tr').forEach(tableRow => {
                tableRow.addEventListener('click', (eventData) => {
                    if(eventData.target.type !== 'checkbox') {
                        const functionCheckbox = tableRow.querySelector('.func-checkbox');
                        if(functionCheckbox) {
                            functionCheckbox.checked = !functionCheckbox.checked;
                            tableRow.classList.toggle('data-grid-row-selected', functionCheckbox.checked);
                        }
                    } else {
                         tableRow.classList.toggle('data-grid-row-selected', eventData.target.checked);
                    }
                })  
            });
        }

        function evaluateGenerationReadiness() {
            const isReadyToGenerate = projectNameInput.value.trim() !== '' && outputDirectoryInput.value.trim() !== '' && activeFunctionsList.length > 0;
            generateProjectButton.disabled = !isReadyToGenerate;
        }

        showDebugButton.addEventListener('click', displayDebugPanel);
        hideDebugButton.addEventListener('click', hideDebugPanel);
        
        processSearchInput.addEventListener('input', () => {
            filterProcessList();
        });

        processSearchInput.addEventListener('keydown', (keyboardEvent) => {
            if (keyboardEvent.key === 'Enter') {
                keyboardEvent.preventDefault();
                const availableOptions = Array.from(processDropdown.options).filter(optionItem => optionItem.value !== '');
                if (availableOptions.length > 0) {
                    processDropdown.value = availableOptions[0].value;
                    processDropdown.dispatchEvent(new Event('change'));
                }
            }
        });

        refreshProcessesButton.addEventListener('click', () => {
            appendToDebugLog("Refresh processes button clicked");
            updateStatusMessage('Refreshing process list...', 'loader-2 animate-spin', 'text-accent');
            window.fetchRunningProcesses();
        });

        processDropdown.addEventListener('change', () => {
            const selectedProcessId = processDropdown.value;
            appendToDebugLog(`Process selected: PID ${selectedProcessId}`);
            activeFunctionsList = [];
            renderFunctionsTable();
            if (!selectedProcessId) {
                moduleListContainer.innerHTML = `<p class="text-primary/50 text-center py-4">Select a process to see its DLLs.</p>`;
                evaluateGenerationReadiness();
                return;
            }
            updateStatusMessage('Loading DLLs...', 'loader-2 animate-spin', 'text-accent');
            window.fetchProcessModules(parseInt(selectedProcessId, 10));
        });

        moduleListContainer.addEventListener('change', (eventData) => {
            if (eventData.target.classList.contains('dll-checkbox')) {
                appendToDebugLog(`DLL checkbox changed: ${eventData.target.dataset.dllName} checked=${eventData.target.checked}`);
                
                if (eventData.target.checked) {
                    document.querySelectorAll('.dll-checkbox').forEach(checkbox => {
                        if (checkbox !== eventData.target) {
                            checkbox.checked = false;
                        }
                    });
                }
                requestFunctionsForActiveModule();
            }
        });

        refreshFunctionsButton.addEventListener('click', () => {
            appendToDebugLog("Refresh functions button clicked");
            requestFunctionsForActiveModule();
        });

        createReportButton.addEventListener('click', triggerReportGeneration);

        searchInput.addEventListener('input', renderFunctionsTable);
        
        selectAllFunctionsCheckbox.addEventListener('change', (eventData) => {
            document.querySelectorAll('.func-checkbox').forEach(checkbox => {
                checkbox.checked = eventData.target.checked;
                checkbox.closest('tr').classList.toggle('data-grid-row-selected', checkbox.checked);
            });
        });

        generateProjectButton.addEventListener('click', () => {
            const selectedFunctionNodes = Array.from(document.querySelectorAll('.func-checkbox:checked'))
                .map(checkbox => {
                    const parentRow = checkbox.closest('tr');
                    return {
                        name: parentRow.dataset.funcName,
                        dll: parentRow.dataset.dllName
                    };
                });

            if (selectedFunctionNodes.length === 0) {
                updateStatusMessage('Error: No functions selected!', 'alert-circle', 'text-red-400');
                setTimeout(() => updateStatusMessage('Ready', '', 'text-primary/80', 0), 2000);
                return;
            }

            const projectOptions = {
                projectName: projectNameInput.value,
                outputDir: outputDirectoryInput.value,
                targetDllPath: activeModulePath,
                functions: selectedFunctionNodes,
                isTargetProcess32Bit: isTargetProcess32Bit 
            };

            window.createProxyProject(JSON.stringify(projectOptions));
        });

        closeAppButton.addEventListener('click', () => window.terminateApplication());
        browseDirectoryButton.addEventListener('click', () => window.promptUserForOutputFolder());
        projectNameInput.addEventListener('input', evaluateGenerationReadiness);
        outputDirectoryInput.addEventListener('input', evaluateGenerationReadiness);

        window.onload = () => {
            appendToDebugLog("Page loaded, initializing...");
            lucide.createIcons();
            updateStatusMessage('Requesting process list...', 'loader-2 animate-spin', 'text-accent');
            window.fetchRunningProcesses();
        };
    </script>
</body>
</html>
)HTML_PART4";

    g_ultralight_controller->LoadHTML(htmlContentText);

    bool shouldExitApplication = false;
    bool isInterfaceVisible = true;
    while (!shouldExitApplication)
    {
        MSG windowMessage;
        while (::PeekMessage(&windowMessage, NULL, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&windowMessage);
            ::DispatchMessage(&windowMessage);
            if (windowMessage.message == WM_QUIT)
                shouldExitApplication = true;
        }
        if (shouldExitApplication)
            break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        DisplayMainInterface(&isInterfaceVisible);

        const float renderClearColor[4] = {0.0f, 0.0f, 0.0f, 0.0f};
        ID3D11RenderTargetView *currentRenderTargetView = GetMainRenderTarget();
        ID3D11DeviceContext *currentDirect3DContext = GetDirect3DDeviceContext();

        if (currentRenderTargetView && currentDirect3DContext)
        {
            currentDirect3DContext->OMSetRenderTargets(1, &currentRenderTargetView, NULL);
            currentDirect3DContext->ClearRenderTargetView(currentRenderTargetView, renderClearColor);
        }

        ImGui::Render();
        if (ImGui::GetDrawData())
        {
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        }

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        IDXGISwapChain *activeSwapChain = GetDirectXSwapChain();
        if (activeSwapChain)
        {
            activeSwapChain->Present(1, 0);
        }
    }

    g_ultralight_controller.reset();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    ShutdownDirect3D();
    ::DestroyWindow(mainWindowHandle);
    DestroyHostWindow(applicationInstance, windowClassName);

    return 0;
}
