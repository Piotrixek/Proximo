// #define NOMINMAX is removed to fix the redefinition warning
#include <Windows.h>
#include <tchar.h>
#include <shellapi.h>
#include <gdiplus.h>
#include <objidl.h>
#include <psapi.h> // For process enumeration
#include <ShlObj.h> // For folder picker dialog
#include <atlbase.h> // For CComPtr

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "dx_setup.h"
#include "ui_style.h"
#include "window_setup.h"

#include "font.h"
#include "icons.h"
#include "ultralight_controller.h"
#include <memory>
#include <string>
#include <vector>
#include <filesystem>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <map>
#include <algorithm> // for std::sort

// Include the LIEF PE header
#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>
#include <menu.h>

// Global controller for our web UI
std::unique_ptr<UltralightController> g_ultralight_controller;


// --- C++ Backend Functions Exposed to JavaScript ---

// Helper to execute JS in the UI thread safely
void SafeEvalScript(std::string script) {
    if (g_ultralight_controller) {
        g_ultralight_controller->evalScript(script);
    }
}

// Helper to convert wstring to utf8 string
std::string to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Called from JS to request the list of running processes
void RequestProcessList(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    std::vector<std::pair<DWORD, std::string>> processes;
    DWORD aProcesses[1024], cbNeeded, cProcesses;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (unsigned int i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            WCHAR szProcessName[MAX_PATH] = L"<unknown>"; // Use WCHAR for Unicode
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            if (NULL != hProcess) {
                HMODULE hMod;
                DWORD cbNeeded2;
                // Explicitly call the Wide version of the function
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded2)) {
                    GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(WCHAR));
                }
                processes.push_back({ aProcesses[i], to_utf8(szProcessName) });
                CloseHandle(hProcess);
            }
        }
    }

    // Sort alphabetically by process name
    std::sort(processes.begin(), processes.end(), [](const auto& a, const auto& b) {
        return a.second < b.second;
        });

    // Build JSON string to pass to the UI
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < processes.size(); ++i) {
        ss << "{ \"pid\": " << processes[i].first << ", \"name\": \"" << processes[i].second << "\" }";
        if (i < processes.size() - 1) ss << ",";
    }
    ss << "]";

    // Call a JS function to populate the dropdown
    SafeEvalScript("populateProcessList(" + ss.str() + ");");
}

// Called from JS to get DLLs for a specific process
void RequestDllsForProcess(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    if (args.size() < 1 || !args[0].IsNumber()) {
        SafeEvalScript("populateDlls([]);");
        return;
    }

    DWORD processID = static_cast<DWORD>(args[0].ToNumber());
    std::vector<std::pair<std::string, std::string>> dlls; // Pair of {name, full_path}
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (NULL == hProcess) {
        SafeEvalScript("populateDlls([]);");
        return;
    }

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            WCHAR szModName[MAX_PATH];
            WCHAR szModPath[MAX_PATH];
            // Explicitly call the Wide versions of the functions
            if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR)) &&
                GetModuleFileNameExW(hProcess, hMods[i], szModPath, sizeof(szModPath) / sizeof(WCHAR)))
            {
                std::string dllName = to_utf8(szModName);
                std::string dllPath = to_utf8(szModPath);

                // escape backslashes for json
                size_t start_pos = 0;
                while ((start_pos = dllPath.find("\\", start_pos)) != std::string::npos) {
                    dllPath.replace(start_pos, 1, "\\\\");
                    start_pos += 2;
                }

                dlls.push_back({ dllName, dllPath });
            }
        }
    }
    CloseHandle(hProcess);

    std::sort(dlls.begin(), dlls.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
        });

    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < dlls.size(); ++i) {
        ss << "{ \"name\": \"" << dlls[i].first << "\", \"path\": \"" << dlls[i].second << "\" }";
        if (i < dlls.size() - 1) ss << ",";
    }
    ss << "]";

    SafeEvalScript("populateDlls(" + ss.str() + ");");
}

// --- Analyze DLLs using LIEF ---
void RequestFunctionsForDlls(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    if (args.size() < 1 || !args[0].IsObject()) {
        SafeEvalScript("populateFunctions([]);");
        return;
    }

    ultralight::JSObject jsArray = args[0].ToObject();
    ultralight::JSValue length_val = jsArray["length"];
    if (!length_val.IsNumber()) return;
    int length = (int)length_val.ToNumber();

    std::stringstream ss;
    ss << "[";
    bool first_func = true;

    for (int i = 0; i < length; ++i) {
        ultralight::JSValue val = jsArray[std::to_string(i).c_str()];
        if (!val.IsString()) continue;

        std::string path = ultralight::String(val.ToString()).utf8().data();
        std::string filename = std::filesystem::path(path).filename().string();

        try {
            std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(path);
            if (binary && binary->has_exports()) {
                LIEF::PE::Export* exp = binary->get_export();
                if (exp) {
                    for (const LIEF::PE::ExportEntry& entry : exp->entries()) {
                        if (!first_func) ss << ",";
                        // Sanitize the name for JSON
                        std::string funcName = entry.name();
                        std::replace(funcName.begin(), funcName.end(), '"', '\'');

                        ss << "{ \"name\": \"" << funcName << "\", "
                            << "\"dll\": \"" << filename << "\", "
                            << "\"type\": \"Export\", "
                            << "\"params\": \"(...)_LIEF\" }";
                        first_func = false;
                    }
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "LIEF parsing error for " << path << ": " << e.what() << std::endl;
        }
    }

    ss << "]";
    SafeEvalScript("populateFunctions(" + ss.str() + ");");
}


// Called from JS to open a folder selection dialog
void SelectOutputDirectory(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(hr)) {
        CComPtr<IFileOpenDialog> pFileOpen;
        hr = pFileOpen.CoCreateInstance(__uuidof(FileOpenDialog));
        if (SUCCEEDED(hr)) {
            pFileOpen->SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
            hr = pFileOpen->Show(NULL);
            if (SUCCEEDED(hr)) {
                CComPtr<IShellItem> pItem;
                hr = pFileOpen->GetResult(&pItem);
                if (SUCCEEDED(hr)) {
                    PWSTR pszFilePath;
                    hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                    if (SUCCEEDED(hr)) {
                        std::string path = to_utf8(pszFilePath);
                        // Need to escape backslashes for JS string
                        size_t start_pos = 0;
                        while ((start_pos = path.find("\\", start_pos)) != std::string::npos) {
                            path.replace(start_pos, 1, "\\\\");
                            start_pos += 2;
                        }
                        SafeEvalScript("setOutputDirectory('" + path + "');");
                        CoTaskMemFree(pszFilePath);
                    }
                }
            }
        }
        CoUninitialize();
    }
}

// Called from JS to generate the final project
void GenerateProject(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    if (args.size() < 1 || !args[0].IsString()) return;
    std::string options_json = ultralight::String(args[0].ToString()).utf8().data();

    // Here you would parse the JSON, get the selected functions, project name, etc.
    // and generate the CMakeLists.txt, dllmain.cpp, and other files.

    std::cout << "Generating project with options: " << options_json << std::endl;

    // Simulate generation process
    SafeEvalScript("updateStatus('Generating files...', 'cog animate-spin', 'text-accent', 30);");
    // ... write files ...
    SafeEvalScript("updateStatus('Running CMake...', 'cog animate-spin', 'text-accent', 70);");
    // ... run cmake command ...
    SafeEvalScript("updateStatus('Project generated successfully!', 'party-popper', 'text-success', 100);");
}

// Called from JS to close the application
void CloseApp(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    PostQuitMessage(0);
}


int main(int, char**)
{
    // Disable LIEF's verbose logging to the console if you don't need it
    LIEF::logging::disable();

    HINSTANCE hInstance = GetModuleHandle(NULL);
    const TCHAR* className = _T("ImGuiAppClass");
    HWND hwnd = SetupWindow(hInstance, className);
    if (!hwnd) {
        return 1;
    }

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::DestroyWindow(hwnd);
        CleanupWindow(hInstance, className);
        return 1;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

    io.IniFilename = nullptr;
    io.LogFilename = nullptr;

    ImFontConfig main_font_config;
    main_font_config.FontDataOwnedByAtlas = false;
    io.Fonts->AddFontFromMemoryTTF((void*)my_Font, sizeof(my_Font), 16.0f, &main_font_config);

    static const ImWchar icons_ranges[] = { 0xf000, 0xf3ff, 0 };
    ImFontConfig icons_config;
    icons_config.MergeMode = true;
    icons_config.PixelSnapH = true;
    icons_config.OversampleH = 3;
    icons_config.OversampleV = 3;
    icons_config.EllipsisChar = 0xf141;
    io.Fonts->AddFontFromMemoryCompressedTTF(font_awesome_data, font_awesome_size, 18.5f, &icons_config, icons_ranges);

    ApplyCommandMenuStyle();

    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowRounding = 0.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(GetDevice(), GetImmediateContext());

    try {
        g_ultralight_controller = std::make_unique<UltralightController>(GetDevice(), GetImmediateContext());
    }
    catch (const std::exception& e) {
        std::string error_msg = "An exception occurred during Ultralight initialization:\n\n";
        error_msg += e.what();
        error_msg += "\n\nThis usually means the 'resources' folder is missing from the executable's directory.";
        MessageBoxA(NULL, error_msg.c_str(), "Ultralight Initialization Failed", MB_OK | MB_ICONERROR);
        return 1;
    }

    if (!g_ultralight_controller->IsRendererValid()) {
        MessageBox(NULL, _T("Failed to initialize Ultralight Renderer!\n\nMake sure the 'resources' and '.dll' files from the SDK are in the same directory as your .exe."), _T("Ultralight Error"), MB_OK | MB_ICONERROR);
        return 1;
    }

    // *** BIND C++ FUNCTIONS TO JAVASCRIPT ***
    g_ultralight_controller->AddCallback("requestProcessList", &RequestProcessList);
    g_ultralight_controller->AddCallback("requestDllsForProcess", &RequestDllsForProcess);
    g_ultralight_controller->AddCallback("requestFunctionsForDlls", &RequestFunctionsForDlls);
    g_ultralight_controller->AddCallback("selectOutputDirectory", &SelectOutputDirectory);
    g_ultralight_controller->AddCallback("generateProject", &GenerateProject);
    g_ultralight_controller->AddCallback("closeApp", &CloseApp);


    std::string html_content = R"HTML_PART1(
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
            overflow: hidden; /* Prevent body scroll */
        }
        /* Custom scrollbar for a more integrated look */
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
    </style>
</head>
)HTML_PART1";

    html_content += R"HTML_PART2(
<body class="bg-primary text-primary antialiased">

    <div class="flex h-screen max-h-screen relative">
        <!-- Close Button -->
        <div id="close-btn" class="absolute top-4 right-4 text-primary/50 hover:text-accent cursor-pointer z-50">
            <i data-lucide="x" class="w-6 h-6"></i>
        </div>

        <!-- Left Panel: Controls -->
        <div class="w-1/3 max-w-sm flex flex-col bg-secondary p-6 space-y-6 overflow-y-auto">
            <!-- Header -->
            <div class="flex-shrink-0">
                <h1 class="text-2xl font-bold text-primary">Proximo</h1>
                <div class="h-0.5 w-16 bg-accent mt-2"></div>
            </div>

            <!-- 1. Process Selection -->
            <div class="space-y-2">
                <label for="process-select" class="text-sm font-semibold text-primary/80">1. Select Process</label>
                <div class="flex items-center space-x-2">
                    <div class="relative flex-grow">
                        <select id="process-select" class="custom-select w-full p-2 rounded-md appearance-none">
                            <option value="">Loading processes...</option>
                        </select>
                        <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-primary/50">
                            <i data-lucide="chevron-down" class="w-4 h-4"></i>
                        </div>
                    </div>
                    <button id="refresh-procs-btn" class="p-2 bg-[#3a3a3a] hover:bg-[#4a4a4a] rounded-md">
                        <i data-lucide="refresh-cw" class="w-4 h-4"></i>
                    </button>
                </div>
            </div>

            <!-- 2. DLL Filtering -->
            <div class="space-y-2 flex-grow flex flex-col min-h-0">
                <label class="text-sm font-semibold text-primary/80">2. Filter DLLs</label>
                <div id="dll-list-container" class="bg-[#2a2a2a] border border-[#4a4a4a] rounded-md p-3 flex-grow overflow-y-auto">
                    <p class="text-primary/50 text-center py-4">Select a process to see its DLLs.</p>
                </div>
            </div>

            <!-- 3. Generation Options -->
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

        <!-- Right Panel: Data View -->
        <div class="w-2/3 flex-grow flex flex-col p-6">
            <div class="flex-shrink-0">
                <h2 class="text-xl font-semibold">Functions Overview</h2>
                <div class="relative mt-4">
                    <i data-lucide="search" class="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-primary/40"></i>
                    <input type="text" id="function-search" placeholder="Filter by function or DLL name..." class="custom-input w-full p-3 pl-10 rounded-md">
                </div>
            </div>

            <!-- Main Data View -->
            <div class="mt-4 flex-grow overflow-y-auto">
                <table class="w-full text-left text-sm">
                    <thead class="sticky top-0">
                        <tr class="data-grid-header text-primary/80">
                            <th class="p-3 w-12"><input type="checkbox" id="select-all-funcs" class="h-4 w-4 rounded bg-[#2a2a2a] border-[#4a4a4a] text-accent focus:ring-accent"></th>
                            <th class="p-3">Function Name</th>
                            <th class="p-3">DLL Name</th>
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

            <!-- Status Bar -->
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

    html_content += R"HTML_PART3(
    <script>
        // --- DOM Elements ---
        const processSelect = document.getElementById('process-select');
        const refreshProcsBtn = document.getElementById('refresh-procs-btn');
        const dllListContainer = document.getElementById('dll-list-container');
        const functionTableBody = document.getElementById('function-table-body');
        const functionSearch = document.getElementById('function-search');
        const selectAllFuncs = document.getElementById('select-all-funcs');
        const statusText = document.getElementById('status-text');
        const statusBarIcon = document.getElementById('status-icon');
        const progressBar = document.getElementById('progress-bar');
        const generateBtn = document.getElementById('generate-btn');
        const closeBtn = document.getElementById('close-btn');
        const browseDirBtn = document.getElementById('browse-dir-btn');
        const outputDirInput = document.getElementById('output-dir');
        const projectNameInput = document.getElementById('project-name');

        let currentFunctions = [];

        // --- UI Update Functions (called from C++) ---
        function populateProcessList(processes) {
            processSelect.innerHTML = '<option value="">Select a running process...</option>';
            processes.forEach(proc => {
                const option = document.createElement('option');
                option.value = proc.pid;
                option.textContent = `${proc.name} (PID: ${proc.pid})`;
                processSelect.appendChild(option);
            });
            updateStatus('Ready. Select a process.', 'list', 'text-primary/80');
        }

        function populateDlls(dlls) {
            if (!dlls || dlls.length === 0) {
                dllListContainer.innerHTML = `<p class="text-primary/50 text-center py-4">No DLLs found for this process.</p>`;
                return;
            }
            dllListContainer.innerHTML = dlls.map(dll => `
                <div class="flex items-center space-x-2 p-1.5 rounded hover:bg-[#3a3a3a]">
                    <input type="checkbox" data-dll-name="${dll.name}" data-dll-path="${dll.path}" class="dll-checkbox h-4 w-4 rounded bg-[#2a2a2a] border-[#4a4a4a] text-accent focus:ring-accent" checked>
                    <label class="text-sm">${dll.name}</label>
                </div>
            `).join('');
            
            // After populating DLLs, automatically request their functions
            requestFunctionsForSelectedDlls();
        }

        function populateFunctions(functions) {
            currentFunctions = functions;
            renderFunctions(); // Initial render
            updateStatus(`Analyzed DLLs. Found ${functions.length} functions.`, 'check-circle', 'text-success');
            setTimeout(() => updateStatus('Ready', '', 'text-primary/80', 0), 3000);
            checkCanGenerate();
        }

        function setOutputDirectory(path) {
            outputDirInput.value = path;
            checkCanGenerate();
        }

        // --- UI Logic ---
        function updateStatus(text, icon = '', colorClass = 'text-primary/80', progress = 0) {
            statusText.textContent = text;
            statusText.className = `text-xs font-medium ${colorClass}`;
            statusBarIcon.innerHTML = icon ? `<i data-lucide="${icon}" class="w-4 h-4"></i>` : '';
            if (icon) lucide.createIcons();
            progressBar.style.width = `${progress}%`;
        }
        
        function requestFunctionsForSelectedDlls() {
            const checkedDllPaths = Array.from(document.querySelectorAll('.dll-checkbox:checked')).map(cb => cb.dataset.dllPath);
            if (checkedDllPaths.length > 0) {
                updateStatus('Analyzing DLLs...', 'loader-2 animate-spin', 'text-accent');
                window.requestFunctionsForDlls(checkedDllPaths);
            } else {
                currentFunctions = [];
                renderFunctions();
            }
        }

        function renderFunctions() {
            const checkedDllNames = Array.from(document.querySelectorAll('.dll-checkbox:checked')).map(cb => cb.dataset.dllName);
            const searchTerm = functionSearch.value.toLowerCase();
            
            const functionsToRender = currentFunctions.filter(f => 
                checkedDllNames.includes(f.dll) &&
                (f.name.toLowerCase().includes(searchTerm) || f.dll.toLowerCase().includes(searchTerm))
            );

            if (functionsToRender.length === 0) {
                functionTableBody.innerHTML = `<tr class="data-grid-row"><td colspan="5" class="text-center p-16 text-primary/50"><i data-lucide="search-x" class="w-12 h-12 mx-auto mb-2"></i><p>No matching functions found.</p></td></tr>`;
                lucide.createIcons();
                return;
            }

            functionTableBody.innerHTML = functionsToRender.map(func => `
                <tr class="data-grid-row border-b border-transparent" data-func-name="${func.name}" data-dll-name="${func.dll}">
                    <td class="p-3"><input type="checkbox" class="func-checkbox h-4 w-4 rounded bg-[#2a2a2a] border-[#4a4a4a] text-accent focus:ring-accent" checked></td>
                    <td class="p-3 font-medium">${func.name}</td>
                    <td class="p-3 text-primary/70">${func.dll}</td>
                    <td class="p-3">
                        <span class="px-2 py-1 text-xs rounded-full ${func.type === 'Export' ? 'bg-blue-900/50 text-blue-300' : 'bg-purple-900/50 text-purple-300'}">
                            ${func.type}
                        </span>
                    </td>
                    <td class="p-3 text-primary/50 font-mono text-xs">${func.params}</td>
                </tr>
            `).join('');
            
            functionTableBody.querySelectorAll('tr').forEach(row => {
                row.addEventListener('click', (e) => {
                    if(e.target.type !== 'checkbox') {
                        const checkbox = row.querySelector('.func-checkbox');
                        if(checkbox) {
                            checkbox.checked = !checkbox.checked;
                            row.classList.toggle('data-grid-row-selected', checkbox.checked);
                        }
                    } else {
                         row.classList.toggle('data-grid-row-selected', e.target.checked);
                    }
                })  
            });
        }

        function checkCanGenerate() {
            const canGenerate = projectNameInput.value.trim() !== '' && outputDirInput.value.trim() !== '' && currentFunctions.length > 0;
            generateBtn.disabled = !canGenerate;
        }

        // --- Event Listeners ---
        refreshProcsBtn.addEventListener('click', () => {
            updateStatus('Refreshing process list...', 'loader-2 animate-spin', 'text-accent');
            window.requestProcessList();
        });

        processSelect.addEventListener('change', () => {
            const pid = processSelect.value;
            functionTableBody.innerHTML = '';
            currentFunctions = [];
            if (!pid) {
                dllListContainer.innerHTML = `<p class="text-primary/50 text-center py-4">Select a process to see its DLLs.</p>`;
                functionTableBody.innerHTML = `<tr class="data-grid-row"><td colspan="5" class="text-center p-16 text-primary/50"><i data-lucide="list-x" class="w-12 h-12 mx-auto mb-2"></i><p>No process selected</p></td></tr>`;
                lucide.createIcons();
                checkCanGenerate();
                return;
            }
            updateStatus('Loading DLLs...', 'loader-2 animate-spin', 'text-accent');
            window.requestDllsForProcess(parseInt(pid, 10));
        });

        dllListContainer.addEventListener('change', (e) => {
            if (e.target.classList.contains('dll-checkbox')) {
                requestFunctionsForSelectedDlls();
            }
        });

        functionSearch.addEventListener('input', renderFunctions);
        
        selectAllFuncs.addEventListener('change', (e) => {
            document.querySelectorAll('.func-checkbox').forEach(cb => {
                cb.checked = e.target.checked;
                cb.closest('tr').classList.toggle('data-grid-row-selected', cb.checked);
            });
        });

        generateBtn.addEventListener('click', () => {
            const selectedFunctions = Array.from(document.querySelectorAll('.func-checkbox:checked'))
                .map(cb => {
                    const row = cb.closest('tr');
                    return {
                        name: row.dataset.funcName,
                        dll: row.dataset.dllName
                    };
                });

            if (selectedFunctions.length === 0) {
                updateStatus('Error: No functions selected!', 'alert-circle', 'text-red-400');
                setTimeout(() => updateStatus('Ready', '', 'text-primary/80', 0), 2000);
                return;
            }

            const options = {
                projectName: projectNameInput.value,
                outputDir: outputDirInput.value,
                functions: selectedFunctions
            };

            window.generateProject(JSON.stringify(options));
        });

        closeBtn.addEventListener('click', () => window.closeApp());
        browseDirBtn.addEventListener('click', () => window.selectOutputDirectory());
        projectNameInput.addEventListener('input', checkCanGenerate);
        outputDirInput.addEventListener('input', checkCanGenerate);

        // --- Initial Load ---
        window.onload = () => {
            lucide.createIcons();
            updateStatus('Requesting process list...', 'loader-2 animate-spin', 'text-accent');
            window.requestProcessList();
        };
    </script>
</body>
</html>
)HTML_PART3";


    g_ultralight_controller->LoadHTML(html_content);

    bool done = false;
    bool show_app = true;
    while (!done)
    {
        MSG msg;
        while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ShowApp(&show_app);

        const float clear_color_with_alpha[4] = { 0.0f, 0.0f, 0.0f, 0.0f };
        ID3D11RenderTargetView* mainRenderTargetView = GetMainRenderTargetView();
        ID3D11DeviceContext* context = GetImmediateContext();

        if (mainRenderTargetView && context) {
            context->OMSetRenderTargets(1, &mainRenderTargetView, NULL);
            context->ClearRenderTargetView(mainRenderTargetView, clear_color_with_alpha);
        }

        ImGui::Render();
        if (ImGui::GetDrawData()) {
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        }

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        IDXGISwapChain* swapChain = GetSwapChain();
        if (swapChain) {
            swapChain->Present(1, 0);
        }
    }

    g_ultralight_controller.reset();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    CleanupWindow(hInstance, className);

    return 0;
}
