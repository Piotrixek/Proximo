#include <Windows.h>
#include <tchar.h>
#include <shellapi.h>
#include <gdiplus.h>
#include <objidl.h>
#include <psapi.h>
#include <ShlObj.h>
#include <atlbase.h>

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
#include <fstream>
#include <stdexcept>
#include <map>
#include <algorithm>
#include <set>
#include <io.h>
#include <fcntl.h>

#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>
#include "menu.h"
#include "json.hpp" // use the json library

// for convenience
using json = nlohmann::json;

std::unique_ptr<UltralightController> g_ultralight_controller;


void SafeEvalScript(std::string script) {
    if (g_ultralight_controller) {
        g_ultralight_controller->evalScript(script);
    }
}

std::string to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

void CopyToClipboard(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    if (args.size() < 1 || !args[0].IsString()) {
        std::cout << "[ERROR] copyToClipboard called with invalid arguments." << std::endl;
        return;
    }

    std::string text_to_copy = ultralight::String(args[0].ToString()).utf8().data();

    if (!OpenClipboard(NULL)) {
        std::cout << "[ERROR] Cannot open the Clipboard." << std::endl;
        return;
    }

    EmptyClipboard();
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, text_to_copy.size() + 1);
    if (!hg) {
        CloseClipboard();
        std::cout << "[ERROR] Cannot allocate memory for clipboard." << std::endl;
        return;
    }

    LPSTR dest = (LPSTR)GlobalLock(hg);
    if (dest) {
        strcpy_s(dest, text_to_copy.size() + 1, text_to_copy.c_str());
        GlobalUnlock(hg);
        SetClipboardData(CF_TEXT, hg);
    }
    else {
        GlobalFree(hg); // clean up if lock fails
    }

    CloseClipboard();
    std::cout << "Successfully copied " << text_to_copy.size() << " bytes to clipboard." << std::endl;
}


void RequestProcessList(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    std::vector<std::pair<DWORD, std::string>> processes;
    DWORD aProcesses[1024], cbNeeded, cProcesses;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (unsigned int i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            WCHAR szProcessName[MAX_PATH] = L"<unknown>";
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            if (NULL != hProcess) {
                HMODULE hMod;
                DWORD cbNeeded2;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded2)) {
                    GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(WCHAR));
                }
                processes.push_back({ aProcesses[i], to_utf8(szProcessName) });
                CloseHandle(hProcess);
            }
        }
    }

    std::sort(processes.begin(), processes.end(), [](const auto& a, const auto& b) {
        return a.second < b.second;
        });

    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < processes.size(); ++i) {
        ss << "{ \"pid\": " << processes[i].first << ", \"name\": \"" << processes[i].second << "\" }";
        if (i < processes.size() - 1) ss << ",";
    }
    ss << "]";

    SafeEvalScript("populateProcessList(" + ss.str() + ");");
}

void RequestDllsForProcess(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    if (args.size() < 1 || !args[0].IsNumber()) {
        SafeEvalScript("populateDlls([]);");
        return;
    }

    DWORD processID = static_cast<DWORD>(args[0].ToNumber());

    const std::set<std::string> system_dlls = {
        // Core OS and C Runtime
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
        "advapi32.dll", "msvcrt.dll", "ucrtbase.dll", "combase.dll", "rpcrt4.dll",
        // Windows Subsystems and Services
        "sechost.dll", "comctl32.dll", "shell32.dll", "shlwapi.dll", "win32u.dll",
        "gdi32full.dll", "msvcp_win.dll", "shcore.dll", "uxtheme.dll",
        // WoW64 (32-bit on 64-bit Windows)
        "wow64.dll", "wow64cpu.dll", "wow64win.dll",
        // Security and Cryptography
        "crypt32.dll", "bcrypt.dll", "bcryptprimitives.dll", "sspicli.dll", "cryptsp.dll",
        // Networking
        "winhttp.dll", "urlmon.dll", "wininet.dll"
    };

    const std::set<std::string> good_dlls = {
        // Graphics APIs (for overlays, rendering hooks)
        "d3d8.dll", "d3d9.dll", "d3d10.dll", "d3d11.dll", "d3d12.dll",
        "dxgi.dll", "opengl32.dll", "glu32.dll", "ddraw.dll",
        "d3dcompiler_43.dll", "d3dcompiler_47.dll",

        // Input APIs (for input hooks, macros)
        "dinput.dll", "dinput8.dll",
        "xinput1_4.dll", "xinput1_3.dll", "xinput1_2.dll", "xinput1_1.dll", "xinput9_1_0.dll",

        // Audio APIs (for audio hooks)
        "dsound.dll", "xaudio2_9.dll", "xaudio2_8.dll", "xaudio2_7.dll",

        // Networking (for packet manipulation)
        "ws2_32.dll",

        // Common Game/Modding Targets (often safe for early injection)
        "winmm.dll", "version.dll",
        "binkw32.dll", "binkw64.dll",
        "steam_api.dll", "steam_api64.dll"
    };

    std::vector<std::string> dlls_json;
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (NULL == hProcess) {
        SafeEvalScript("populateDlls([]);");
        return;
    }

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        bool first_selectable_found = false;
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            WCHAR szModName[MAX_PATH];
            WCHAR szModPath[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR)) &&
                GetModuleFileNameExW(hProcess, hMods[i], szModPath, sizeof(szModPath) / sizeof(WCHAR)))
            {
                std::string dllName = to_utf8(szModName);
                std::string dllPath = to_utf8(szModPath);

                std::string lowerDllName = dllName;
                std::transform(lowerDllName.begin(), lowerDllName.end(), lowerDllName.begin(), ::tolower);

                std::string dllCategory = "neutral";
                if (system_dlls.count(lowerDllName) > 0) {
                    dllCategory = "system";
                }
                else if (good_dlls.count(lowerDllName) > 0) {
                    dllCategory = "good";
                }

                bool is_selectable = (dllCategory != "system");
                bool is_selected = false;
                if (is_selectable && !first_selectable_found) {
                    is_selected = true;
                    first_selectable_found = true;
                }

                size_t start_pos = 0;
                while ((start_pos = dllPath.find("\\", start_pos)) != std::string::npos) {
                    dllPath.replace(start_pos, 1, "\\\\");
                    start_pos += 2;
                }

                std::stringstream ss;
                ss << "{ \"name\": \"" << dllName << "\", \"path\": \"" << dllPath
                    << "\", \"selected\": " << (is_selected ? "true" : "false")
                    << ", \"category\": \"" << dllCategory << "\" }";
                dlls_json.push_back(ss.str());
            }
        }
    }
    CloseHandle(hProcess);

    std::sort(dlls_json.begin(), dlls_json.end(), [](const std::string& a, const std::string& b) {
        // this sort puts good/neutral dlls first
        bool a_is_system = a.find("\"category\": \"system\"") != std::string::npos;
        bool b_is_system = b.find("\"category\": \"system\"") != std::string::npos;
        if (a_is_system != b_is_system) {
            return !a_is_system;
        }
        return a < b;
        });

    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < dlls_json.size(); ++i) {
        ss << dlls_json[i];
        if (i < dlls_json.size() - 1) ss << ",";
    }
    ss << "]";

    SafeEvalScript("populateDlls(" + ss.str() + ");");
}

std::string getFunctionsAsJsonString(std::string& path) {
    size_t start_pos = 0;
    while ((start_pos = path.find("\\\\", start_pos)) != std::string::npos) {
        path.replace(start_pos, 2, "\\");
        start_pos += 1;
    }

    if (!std::filesystem::exists(path)) {
        return "";
    }

    std::stringstream ss;
    std::string filename = std::filesystem::path(path).filename().string();

    try {
        std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(path);
        if (!binary || !binary->has_exports()) {
            return "";
        }

        bool first_func = true;
        for (const LIEF::PE::ExportEntry& entry : binary->get_export()->entries()) {
            if (!first_func) ss << ",";

            std::string funcName = entry.name();
            if (funcName.empty()) {
                funcName = "ordinal_" + std::to_string(entry.ordinal());
            }

            std::replace(funcName.begin(), funcName.end(), '"', '\'');
            std::replace(funcName.begin(), funcName.end(), '\\', '/');

            ss << "{ \"name\": \"" << funcName << "\", "
                << "\"dll\": \"" << filename << "\", "
                << "\"type\": \"Export\", "
                << "\"params\": \"(...)\" }";
            first_func = false;
        }
    }
    catch (const std::exception&) {
        return "";
    }

    return ss.str();
}

void RequestFunctionsForDlls(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    if (args.size() < 1 || !args[0].IsString()) {
        SafeEvalScript("populateFunctions([]);");
        return;
    }
    std::string path = ultralight::String(args[0].ToString()).utf8().data();
    std::string functions_json = getFunctionsAsJsonString(path);
    SafeEvalScript("populateFunctions([" + functions_json + "]);");
}

void RequestFunctionsForMultipleDlls(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    if (args.size() < 1 || !args[0].IsArray()) {
        SafeEvalScript("populateReportData([]);");
        return;
    }

    ultralight::JSArray dllPathsArray = args[0].ToArray();
    std::stringstream aggregated_results;
    aggregated_results << "[";
    bool first_entry = true;

    for (size_t i = 0; i < dllPathsArray.length(); ++i) {
        std::string path = ultralight::String(dllPathsArray[i].ToString()).utf8().data();
        std::string functions_json = getFunctionsAsJsonString(path);

        if (!functions_json.empty()) {
            if (!first_entry) {
                aggregated_results << ",";
            }
            aggregated_results << functions_json;
            first_entry = false;
        }
    }

    aggregated_results << "]";
    SafeEvalScript("populateReportData(" + aggregated_results.str() + ");");
}


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

void GenerateProject(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    SafeEvalScript("updateStatus('Starting project generation...', 'cog', 'text-accent', 10);");

    if (args.size() < 1 || !args[0].IsString()) {
        SafeEvalScript("updateStatus('Error: Invalid args for generation.', 'bug', 'text-red-400', 0);");
        return;
    }
    std::string options_str = ultralight::String(args[0].ToString()).utf8().data();
    std::cout << "Generating project with options: " << options_str << std::endl;

    try {
        json opts = json::parse(options_str);
        std::string projectName = opts["projectName"];
        std::string outputDirStr = opts["outputDir"];
        std::string targetDllPathStr = opts["targetDllPath"];

        std::filesystem::path outputDir(outputDirStr);
        std::filesystem::path targetDllPath(targetDllPathStr);

        std::filesystem::create_directories(outputDir);
        SafeEvalScript("updateStatus('Created project directory...', 'folder-plus', 'text-accent', 25);");

        auto original_binary = LIEF::PE::Parser::parse(targetDllPath.string());
        if (!original_binary || !original_binary->has_exports()) {
            SafeEvalScript("updateStatus('Error: Could not analyze target DLL.', 'alert-triangle', 'text-red-400', 0);");
            return;
        }

        std::set<std::string> selected_func_names;
        for (const auto& func : opts["functions"]) {
            selected_func_names.insert(func["name"]);
        }

        std::vector<LIEF::PE::ExportEntry> selected_exports;
        for (const auto& entry : original_binary->get_export()->entries()) {
            if (selected_func_names.count(entry.name())) {
                selected_exports.push_back(entry);
            }
        }

        // --- Generate CMakeLists.txt ---
        std::ofstream cmake_file(outputDir / "CMakeLists.txt");
        cmake_file << "cmake_minimum_required(VERSION 3.15)\n"
            << "project(" << projectName << " LANGUAGES CXX ASM_MASM)\n\n"
            << "set(CMAKE_CXX_STANDARD 17)\n"
            << "set(CMAKE_CXX_STANDARD_REQUIRED True)\n\n"
            << "add_library(" << projectName << " SHARED\n"
            << "    dllmain.cpp\n"
            << "    proxy.asm\n"
            << ")\n\n"
            << "if(MSVC)\n"
            << "    set_target_properties(" << projectName << " PROPERTIES\n"
            << "        LINK_FLAGS \"/DEF:\\\"${CMAKE_CURRENT_SOURCE_DIR}/" << projectName << ".def\\\"\"\n"
            << "    )\n"
            << "endif()";
        cmake_file.close();
        SafeEvalScript("updateStatus('Generating build system...', 'wrench', 'text-accent', 40);");

        // --- Generate .def file ---
        std::ofstream def_file(outputDir / (projectName + ".def"));
        def_file << "LIBRARY " << projectName << "\n";
        def_file << "EXPORTS\n";
        for (const auto& entry : selected_exports) {
            def_file << "    " << entry.name() << " @" << entry.ordinal() << "\n";
        }
        def_file.close();

        // --- Generate proxy.h ---
        std::ofstream proxy_h_file(outputDir / "proxy.h");
        proxy_h_file << "#pragma once\n"
            << "#include <windows.h>\n\n"
            << "extern \"C\" {\n";
        for (const auto& entry : selected_exports) {
            proxy_h_file << "    extern FARPROC pfn" << entry.name() << ";\n";
        }
        proxy_h_file << "}\n";
        proxy_h_file.close();

        // --- Generate dllmain.cpp ---
        std::string originalDllName = targetDllPath.stem().string() + "_original.dll";
        std::ofstream dllmain_file(outputDir / "dllmain.cpp");
        dllmain_file << "#include \"proxy.h\"\n"
            << "#include <string>\n\n"
            << "HMODULE hOriginalDll = NULL;\n"
            << "const std::string originalDllName = \"" << originalDllName << "\";\n\n"
            << "extern \"C\" {\n";
        for (const auto& entry : selected_exports) {
            dllmain_file << "    FARPROC pfn" << entry.name() << " = NULL;\n";
        }
        dllmain_file << "}\n\n"
            << "void InitializeProxies(HMODULE hMod) {\n";
        for (const auto& entry : selected_exports) {
            dllmain_file << "    pfn" << entry.name() << " = GetProcAddress(hMod, \"" << entry.name() << "\");\n";
        }
        dllmain_file << "}\n\n"
            << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n"
            << "    switch (ul_reason_for_call) {\n"
            << "        case DLL_PROCESS_ATTACH:\n"
            << "            DisableThreadLibraryCalls(hModule);\n"
            << "            hOriginalDll = LoadLibraryA(originalDllName.c_str());\n"
            << "            if (hOriginalDll) {\n"
            << "                InitializeProxies(hOriginalDll);\n"
            << "                MessageBoxA(NULL, \"Proximo proxy DLL loaded successfully!\", \"Proxy Loaded\", MB_OK | MB_ICONINFORMATION);\n"
            << "            } else {\n"
            << "                MessageBoxA(NULL, \"Failed to load original DLL.\", \"Proxy Error\", MB_OK | MB_ICONERROR);\n"
            << "                return FALSE;\n"
            << "            }\n"
            << "            break;\n"
            << "        case DLL_PROCESS_DETACH:\n"
            << "            if (hOriginalDll) FreeLibrary(hOriginalDll);\n"
            << "            break;\n"
            << "    }\n"
            << "    return TRUE;\n"
            << "}";
        dllmain_file.close();
        SafeEvalScript("updateStatus('Generating source files...', 'file-code', 'text-accent', 70);");

        // --- Generate proxy.asm ---
        std::ofstream proxy_asm_file(outputDir / "proxy.asm");
        for (const auto& entry : selected_exports) {
            proxy_asm_file << "EXTERN pfn" << entry.name() << ":QWORD\n";
        }
        proxy_asm_file << "\n.CODE\n\n";
        for (const auto& entry : selected_exports) {
            proxy_asm_file << "PUBLIC " << entry.name() << "\n"
                << entry.name() << " PROC\n"
                << "    jmp qword ptr [pfn" << entry.name() << "]\n"
                << entry.name() << " ENDP\n\n";
        }
        proxy_asm_file << "END\n";
        proxy_asm_file.close();

        SafeEvalScript("updateStatus('Project generated successfully!', 'party-popper', 'text-success', 100);");
        std::cout << "Project generated successfully in " << outputDirStr << std::endl;

    }
    catch (const json::exception& e) {
        std::cout << "[FATAL] JSON parsing error: " << e.what() << std::endl;
        SafeEvalScript("updateStatus('Error: Failed to parse generation options.', 'bug', 'text-red-400', 0);");
    }
    catch (const std::exception& e) {
        std::cout << "[FATAL] File generation error: " << e.what() << std::endl;
        SafeEvalScript("updateStatus('Error: Could not write project files.', 'file-x', 'text-red-400', 0);");
    }
}


void CloseApp(const ultralight::JSObject& thisObject, const ultralight::JSArgs& args) {
    PostQuitMessage(0);
}

void make_console() {
    if (AllocConsole()) {
        FILE* p_cout;
        freopen_s(&p_cout, "CONOUT$", "w", stdout);
        freopen_s(&p_cout, "CONOUT$", "w", stderr);
        SetConsoleTitle("Proximo Debug Console");
        std::cout.clear();
        std::wcout.clear();
        std::cerr.clear();
        std::wcerr.clear();
        std::cout << "heyo! debug console is on" << std::endl;
    }
}


int main(int, char**)
{
    make_console();
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

    g_ultralight_controller->AddCallback("requestProcessList", &RequestProcessList);
    g_ultralight_controller->AddCallback("requestDllsForProcess", &RequestDllsForProcess);
    g_ultralight_controller->AddCallback("requestFunctionsForDlls", &RequestFunctionsForDlls);
    g_ultralight_controller->AddCallback("requestFunctionsForMultipleDlls", &RequestFunctionsForMultipleDlls);
    g_ultralight_controller->AddCallback("selectOutputDirectory", &SelectOutputDirectory);
    g_ultralight_controller->AddCallback("generateProject", &GenerateProject);
    g_ultralight_controller->AddCallback("closeApp", &CloseApp);
    g_ultralight_controller->AddCallback("copyToClipboard", &CopyToClipboard);


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

    html_content += R"HTML_PART2(
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
        const refreshFuncsBtn = document.getElementById('refresh-funcs-btn');
        const generateReportBtn = document.getElementById('generate-report-btn');
        const debugBtn = document.getElementById('debug-btn');
        const debugPanel = document.getElementById('debug-panel');
        const debugContent = document.getElementById('debug-content');
        const closeDebugBtn = document.getElementById('close-debug-btn');

        let currentFunctions = [];
        let reportFunctions = [];
        let currentDllPath = ''; // store the path of the selected dll
        let debugLog = "=== JAVASCRIPT DEBUG LOG ===\n\n";

        function addDebugLog(message) {
            const timestamp = new Date().toLocaleTimeString();
            debugLog += `[${timestamp}] ${message}\n`;
            debugContent.textContent = debugLog;
        }

        function showDebug() {
            debugPanel.style.display = 'flex';
            lucide.createIcons();
        }

        function hideDebug() {
            debugPanel.style.display = 'none';
        }

        function populateProcessList(processes) {
            addDebugLog(`populateProcessList called with ${processes.length} processes`);
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
			addDebugLog(`populateDlls called with ${dlls.length} DLLs`);
			if (!dlls || dlls.length === 0) {
				dllListContainer.innerHTML = `<p class="text-primary/50 text-center py-4">No DLLs found for this process.</p>`;
				return;
			}
			
			dllListContainer.innerHTML = dlls.map(dll => {
				const escapedPath = dll.path.replace(/"/g, '&quot;');
				const escapedName = dll.name.replace(/"/g, '&quot;');
                
                let labelClass = '';
                let isDisabled = false;
                switch(dll.category) {
                    case 'system':
                        labelClass = 'text-red-400';
                        isDisabled = true;
                        break;
                    case 'good':
                        labelClass = 'text-green-400';
                        break;
                    case 'neutral':
                    default:
                        labelClass = '';
                        break;
                }
                const disabledAttr = isDisabled ? 'disabled' : '';
				
				return `
				<div class="flex items-center space-x-2 p-1.5 rounded hover:bg-[#3a3a3a]">
					<input type="checkbox" 
						   data-dll-name="${escapedName}" 
						   data-dll-path="${escapedPath}" 
						   class="dll-checkbox h-4 w-4 rounded bg-[#2a2a2a] border-[#4a4a4a] text-accent focus:ring-accent" 
						   ${dll.selected ? 'checked' : ''} ${disabledAttr}>
					<label class="text-sm ${labelClass}">${escapedName}</label>
				</div>`;
			}).join('');
			
			requestFunctionsForSelectedDlls();
		}

        function populateFunctions(functions) {
            addDebugLog(`populateFunctions called with ${functions.length} functions`);
            currentFunctions = functions;
            renderFunctions();
            checkCanGenerate();
            
            if (functions.length > 0) {
                updateStatus(`Analysis complete. Found ${functions.length} functions.`, 'check-circle', 'text-success');
                setTimeout(() => updateStatus('Ready', '', 'text-primary/80', 0), 4000);
            } else if (document.querySelectorAll('.dll-checkbox:checked').length > 0) {
                updateStatus('Analysis complete. No exported functions found.', 'search-x', 'text-primary/80');
            }
        }
        
        function populateReportData(functions) {
            addDebugLog(`Received data for report with ${functions.length} total functions.`);
            reportFunctions = functions;
            formatAndCopyReport();
        }
        
        function formatAndCopyReport() {
            if (reportFunctions.length === 0) {
                updateStatus('No functions found in selected DLLs to report.', 'alert-circle', 'text-primary/80');
                setTimeout(() => updateStatus('Ready', '', 'text-primary/80'), 3000);
                return;
            }

            const dllsToReport = reportFunctions.reduce((acc, func) => {
                if (!acc[func.dll]) {
                    acc[func.dll] = [];
                }
                acc[func.dll].push(func);
                return acc;
            }, {});

            let reportText = `Proximo DLL & Function Report\nGenerated on: ${new Date().toLocaleString()}\n\n`;

            for (const dllName in dllsToReport) {
                reportText += `--- DLL: ${dllName} ---\n`;
                
                const functionsForDll = dllsToReport[dllName];
                const functionsToShow = functionsForDll.slice(0, 10);
                
                functionsToShow.forEach(func => {
                    reportText += `- Function: ${(func.name || '').padEnd(40)} | Type: ${(func.type || '').padEnd(8)} | Params: ${func.params}\n`;
                });
                
                if (functionsForDll.length > 10) {
                    reportText += `...and ${functionsForDll.length - 10} more functions.\n`;
                }
                reportText += '\n';
            }

            window.copyToClipboard(reportText);
            addDebugLog('Report passed to C++ for copying.');
            updateStatus('Report copied to clipboard!', 'copy', 'text-success');
            setTimeout(() => updateStatus('Ready', '', 'text-primary/80'), 3000);
        }

        function generateAndCopyReport() {
            addDebugLog('Generate report button clicked');
            
            const dllCheckboxes = document.querySelectorAll('.dll-checkbox:not([disabled])');
            if (dllCheckboxes.length === 0) {
                updateStatus('No proxyable DLLs found to report on.', 'alert-circle', 'text-red-400');
                setTimeout(() => updateStatus('Ready', '', 'text-primary/80'), 3000);
                return;
            }
            
            const allProxyableDllPaths = Array.from(dllCheckboxes)
                                              .map(cb => cb.getAttribute('data-dll-path'));

            if (allProxyableDllPaths.length > 0) {
                updateStatus(`Analyzing ${allProxyableDllPaths.length} DLLs for report...`, 'loader-2 animate-spin', 'text-accent');
                window.requestFunctionsForMultipleDlls(allProxyableDllPaths);
            }
        }

        function setOutputDirectory(path) {
            addDebugLog(`setOutputDirectory called with path: ${path}`);
            outputDirInput.value = path;
            checkCanGenerate();
        }

)HTML_PART3";

    html_content += R"HTML_PART4(
        function updateStatus(text, icon = '', colorClass = 'text-primary/80', progress = 0) {
            statusText.textContent = text;
            statusText.className = `text-xs font-medium ${colorClass}`;
            statusBarIcon.innerHTML = icon ? `<i data-lucide="${icon}" class="w-4 h-4"></i>` : '';
            if (icon) lucide.createIcons();
            progressBar.style.width = `${progress}%`;
        }
        
        function requestFunctionsForSelectedDlls() {
			addDebugLog("=== requestFunctionsForSelectedDlls CALLED ===");
			
			const checkedBox = document.querySelector('.dll-checkbox:checked');
			
			if (checkedBox) {
				const dllPath = checkedBox.getAttribute('data-dll-path');
				const dllName = checkedBox.getAttribute('data-dll-name');
                currentDllPath = dllPath; // save for project generation
				
				addDebugLog(`Found selected DLL: "${dllName}" with path: "${dllPath}"`);

				if (dllPath && dllPath !== 'null' && dllPath.length > 0) {
					addDebugLog(`Calling C++ with string argument: "${dllPath}"`);
					updateStatus(`Analyzing ${dllName}...`, 'loader-2 animate-spin', 'text-accent', 50);
					
					window.requestFunctionsForDlls(dllPath); 
					addDebugLog("Call to C++ completed.");
				} else {
					addDebugLog("ERROR: Selected DLL path is invalid.");
                    currentDllPath = '';
					updateStatus('Error: Selected DLL has no path data.', 'alert-circle', 'text-red-400');
					populateFunctions([]);
				}
			} else {
				addDebugLog("No DLL is selected.");
                currentDllPath = '';
				updateStatus('Ready', '', 'text-primary/80');
				populateFunctions([]);
			}
			addDebugLog("=== requestFunctionsForSelectedDlls FINISHED ===\n");
		}


        function renderFunctions() {
            const checkedDllNames = Array.from(document.querySelectorAll('.dll-checkbox:checked')).map(cb => cb.dataset.dllName);
            const searchTerm = functionSearch.value.toLowerCase();
            
            const functionsToRender = currentFunctions.filter(f => 
                checkedDllNames.includes(f.dll) &&
                (f.name.toLowerCase().includes(searchTerm) || f.dll.toLowerCase().includes(searchTerm))
            );

            if (functionsToRender.length === 0) {
                if (checkedDllNames.length > 0) {
                     functionTableBody.innerHTML = `<tr class="data-grid-row"><td colspan="5" class="text-center p-16 text-primary/50"><i data-lucide="search-x" class="w-12 h-12 mx-auto mb-2"></i><p>No matching functions found for the selected DLL.</p></td></tr>`;
                } else {
                    functionTableBody.innerHTML = `<tr class="data-grid-row"><td colspan="5" class="text-center p-16 text-primary/50"><i data-lucide="list-x" class="w-12 h-12 mx-auto mb-2"></i><p>Select a DLL to see functions.</p></td></tr>`;
                }
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

        // Event Listeners
        debugBtn.addEventListener('click', showDebug);
        closeDebugBtn.addEventListener('click', hideDebug);
        
        refreshProcsBtn.addEventListener('click', () => {
            addDebugLog("Refresh processes button clicked");
            updateStatus('Refreshing process list...', 'loader-2 animate-spin', 'text-accent');
            window.requestProcessList();
        });

        processSelect.addEventListener('change', () => {
            const pid = processSelect.value;
            addDebugLog(`Process selected: PID ${pid}`);
            currentFunctions = [];
            renderFunctions();
            if (!pid) {
                dllListContainer.innerHTML = `<p class="text-primary/50 text-center py-4">Select a process to see its DLLs.</p>`;
                checkCanGenerate();
                return;
            }
            updateStatus('Loading DLLs...', 'loader-2 animate-spin', 'text-accent');
            window.requestDllsForProcess(parseInt(pid, 10));
        });

        dllListContainer.addEventListener('change', (e) => {
            if (e.target.classList.contains('dll-checkbox')) {
                addDebugLog(`DLL checkbox changed: ${e.target.dataset.dllName} checked=${e.target.checked}`);
                
                if (e.target.checked) {
                    document.querySelectorAll('.dll-checkbox').forEach(cb => {
                        if (cb !== e.target) {
                            cb.checked = false;
                        }
                    });
                }
                requestFunctionsForSelectedDlls();
            }
        });

        refreshFuncsBtn.addEventListener('click', () => {
            addDebugLog("Refresh functions button clicked");
            requestFunctionsForSelectedDlls();
        });

        generateReportBtn.addEventListener('click', generateAndCopyReport);

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
                targetDllPath: currentDllPath, // send the full path
                functions: selectedFunctions
            };

            window.generateProject(JSON.stringify(options));
        });

        closeBtn.addEventListener('click', () => window.closeApp());
        browseDirBtn.addEventListener('click', () => window.selectOutputDirectory());
        projectNameInput.addEventListener('input', checkCanGenerate);
        outputDirInput.addEventListener('input', checkCanGenerate);

        window.onload = () => {
            addDebugLog("Page loaded, initializing...");
            lucide.createIcons();
            updateStatus('Requesting process list...', 'loader-2 animate-spin', 'text-accent');
            window.requestProcessList();
        };
    </script>
</body>
</html>
)HTML_PART4";


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