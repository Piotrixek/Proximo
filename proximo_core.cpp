#include "proximo_core.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <ShlObj.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>

void EnableDebugPrivilege()
{
    HANDLE processTokenHandle = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processTokenHandle))
    {
        TOKEN_PRIVILEGES tokenPrivileges;
        LUID locallyUniqueIdentifier;
        if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &locallyUniqueIdentifier))
        {
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges[0].Luid = locallyUniqueIdentifier;
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(processTokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
        CloseHandle(processTokenHandle);
    }
}

std::string ConvertWideStringToUtf8(const std::wstring &wideString)
{
    if (wideString.empty())
    {
        return std::string();
    }
    int requiredSize = WideCharToMultiByte(CP_UTF8, 0, &wideString[0], static_cast<int>(wideString.size()), NULL, 0, NULL, NULL);
    std::string utf8String(requiredSize, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wideString[0], static_cast<int>(wideString.size()), &utf8String[0], requiredSize, NULL, NULL);
    return utf8String;
}

DWORD FindProcessIdentifierByNameOrString(const std::string &identifierOrName)
{
    if (identifierOrName.empty())
    {
        return 0;
    }

    bool isNumericString = true;
    for (char characterItem : identifierOrName)
    {
        if (!isdigit(static_cast<unsigned char>(characterItem)))
        {
            isNumericString = false;
            break;
        }
    }

    if (isNumericString)
    {
        try
        {
            return static_cast<DWORD>(std::stoul(identifierOrName));
        }
        catch (const std::exception &)
        {
        }
    }

    std::string normalizedTarget = identifierOrName;
    std::transform(normalizedTarget.begin(), normalizedTarget.end(), normalizedTarget.begin(), ::tolower);
    if (normalizedTarget.size() > 4 && normalizedTarget.substr(normalizedTarget.size() - 4) == ".exe")
    {
        normalizedTarget = normalizedTarget.substr(0, normalizedTarget.size() - 4);
    }

    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshotHandle != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(snapshotHandle, &processEntry))
        {
            do
            {
                std::string currentProcessName = ConvertWideStringToUtf8(processEntry.szExeFile);
                std::string lowerProcessName = currentProcessName;
                std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);

                std::string baseExecutableName = lowerProcessName;
                if (baseExecutableName.size() > 4 && baseExecutableName.substr(baseExecutableName.size() - 4) == ".exe")
                {
                    baseExecutableName = baseExecutableName.substr(0, baseExecutableName.size() - 4);
                }

                if (baseExecutableName == normalizedTarget || lowerProcessName == normalizedTarget || lowerProcessName == (normalizedTarget + ".exe"))
                {
                    DWORD resolvedIdentifier = processEntry.th32ProcessID;
                    CloseHandle(snapshotHandle);
                    return resolvedIdentifier;
                }
            } while (Process32NextW(snapshotHandle, &processEntry));
        }
        CloseHandle(snapshotHandle);
    }

    return 0;
}

struct ProcessInformationRecord
{
    DWORD processIdentifier;
    std::string processName;
    std::string executablePath;
    double workingSetMegaBytes;
    bool is32Bit;
};

json GetRunningProcesses(const std::string &filterQuery)
{
    EnableDebugPrivilege();

    std::map<DWORD, ProcessInformationRecord> detectedProcessesMap;

    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshotHandle != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshotHandle, &processEntry))
        {
            do
            {
                if (processEntry.th32ProcessID != 0)
                {
                    std::string processName = ConvertWideStringToUtf8(processEntry.szExeFile);
                    if (!processName.empty())
                    {
                        ProcessInformationRecord processRecord;
                        processRecord.processIdentifier = processEntry.th32ProcessID;
                        processRecord.processName = processName;
                        processRecord.executablePath = "";
                        processRecord.workingSetMegaBytes = 0.0;
                        processRecord.is32Bit = false;

                        detectedProcessesMap[processEntry.th32ProcessID] = processRecord;
                    }
                }
            } while (Process32NextW(snapshotHandle, &processEntry));
        }
        CloseHandle(snapshotHandle);
    }

    DWORD processIdentifiersArray[4096];
    DWORD bytesReturned = 0;
    if (EnumProcesses(processIdentifiersArray, sizeof(processIdentifiersArray), &bytesReturned))
    {
        DWORD totalProcessCount = bytesReturned / sizeof(DWORD);
        for (DWORD processIndex = 0; processIndex < totalProcessCount; processIndex++)
        {
            DWORD currentProcessIdentifier = processIdentifiersArray[processIndex];
            if (currentProcessIdentifier == 0)
            {
                continue;
            }

            if (detectedProcessesMap.find(currentProcessIdentifier) == detectedProcessesMap.end())
            {
                ProcessInformationRecord fallbackRecord;
                fallbackRecord.processIdentifier = currentProcessIdentifier;
                fallbackRecord.processName = "<unknown>";
                fallbackRecord.executablePath = "";
                fallbackRecord.workingSetMegaBytes = 0.0;
                fallbackRecord.is32Bit = false;

                detectedProcessesMap[currentProcessIdentifier] = fallbackRecord;
            }
        }
    }

    for (auto &processMapPair : detectedProcessesMap)
    {
        HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processMapPair.first);
        if (processHandle != NULL)
        {
            WCHAR fullImagePathBuffer[MAX_PATH];
            DWORD pathBufferSize = MAX_PATH;
            if (QueryFullProcessImageNameW(processHandle, 0, fullImagePathBuffer, &pathBufferSize))
            {
                processMapPair.second.executablePath = ConvertWideStringToUtf8(fullImagePathBuffer);
                if (processMapPair.second.processName == "<unknown>" || processMapPair.second.processName.empty())
                {
                    std::filesystem::path resolvedPath(fullImagePathBuffer);
                    processMapPair.second.processName = ConvertWideStringToUtf8(resolvedPath.filename().wstring());
                }
            }

            BOOL isTargetWow64 = FALSE;
            if (IsWow64Process(processHandle, &isTargetWow64))
            {
                processMapPair.second.is32Bit = (isTargetWow64 == TRUE);
            }

            PROCESS_MEMORY_COUNTERS processMemoryCounters;
            if (GetProcessMemoryInfo(processHandle, &processMemoryCounters, sizeof(processMemoryCounters)))
            {
                processMapPair.second.workingSetMegaBytes = static_cast<double>(processMemoryCounters.WorkingSetSize) / (1024.0 * 1024.0);
            }

            CloseHandle(processHandle);
        }
    }

    std::string normalizedFilter = filterQuery;
    std::transform(normalizedFilter.begin(), normalizedFilter.end(), normalizedFilter.begin(), ::tolower);

    std::vector<ProcessInformationRecord> filteredProcessesList;
    for (const auto &processMapPair : detectedProcessesMap)
    {
        const ProcessInformationRecord &currentRecord = processMapPair.second;
        if (!normalizedFilter.empty())
        {
            std::string lowerProcessName = currentRecord.processName;
            std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);

            std::string lowerPath = currentRecord.executablePath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

            std::string pidString = std::to_string(currentRecord.processIdentifier);

            bool matchesName = lowerProcessName.find(normalizedFilter) != std::string::npos;
            bool matchesPath = lowerPath.find(normalizedFilter) != std::string::npos;
            bool matchesPid = pidString.find(normalizedFilter) != std::string::npos;

            if (!matchesName && !matchesPath && !matchesPid)
            {
                continue;
            }
        }
        filteredProcessesList.push_back(currentRecord);
    }

    std::sort(filteredProcessesList.begin(), filteredProcessesList.end(), [](const ProcessInformationRecord &firstItem, const ProcessInformationRecord &secondItem) {
        std::string firstLower = firstItem.processName;
        std::string secondLower = secondItem.processName;
        std::transform(firstLower.begin(), firstLower.end(), firstLower.begin(), ::tolower);
        std::transform(secondLower.begin(), secondLower.end(), secondLower.begin(), ::tolower);
        if (firstLower != secondLower)
        {
            return firstLower < secondLower;
        }
        return firstItem.processIdentifier < secondItem.processIdentifier;
    });

    json processListJsonArray = json::array();
    for (const auto &processItem : filteredProcessesList)
    {
        json singleObject;
        singleObject["processIdentifier"] = processItem.processIdentifier;
        singleObject["processName"] = processItem.processName;
        singleObject["executablePath"] = processItem.executablePath.empty() ? nullptr : json(processItem.executablePath);
        singleObject["workingSetMegaBytes"] = processItem.workingSetMegaBytes;
        singleObject["is32BitProcess"] = processItem.is32Bit;
        singleObject["architecture"] = processItem.is32Bit ? "x86" : "x64";
        processListJsonArray.push_back(singleObject);
    }

    json resultPayload;
    resultPayload["isSuccessful"] = true;
    resultPayload["status"] = "success";
    resultPayload["totalFoundCount"] = filteredProcessesList.size();
    resultPayload["processes"] = processListJsonArray;

    return resultPayload;
}

json GetProcessDetails(DWORD processIdentifier)
{
    EnableDebugPrivilege();

    if (processIdentifier == 0)
    {
        json errorPayload;
        errorPayload["isSuccessful"] = false;
        errorPayload["status"] = "error";
        errorPayload["errorMessage"] = "Invalid process identifier";
        return errorPayload;
    }

    std::string processName;
    std::string executablePath;
    double workingSetMegaBytes = 0.0;
    bool is32BitProcess = false;

    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshotHandle != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(snapshotHandle, &processEntry))
        {
            do
            {
                if (processEntry.th32ProcessID == processIdentifier)
                {
                    processName = ConvertWideStringToUtf8(processEntry.szExeFile);
                    break;
                }
            } while (Process32NextW(snapshotHandle, &processEntry));
        }
        CloseHandle(snapshotHandle);
    }

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processIdentifier);
    if (processHandle != NULL)
    {
        WCHAR fullImagePathBuffer[MAX_PATH];
        DWORD pathBufferSize = MAX_PATH;
        if (QueryFullProcessImageNameW(processHandle, 0, fullImagePathBuffer, &pathBufferSize))
        {
            executablePath = ConvertWideStringToUtf8(fullImagePathBuffer);
            if (processName.empty())
            {
                std::filesystem::path resolvedPath(fullImagePathBuffer);
                processName = ConvertWideStringToUtf8(resolvedPath.filename().wstring());
            }
        }

        BOOL isTargetWow64 = FALSE;
        if (IsWow64Process(processHandle, &isTargetWow64))
        {
            is32BitProcess = (isTargetWow64 == TRUE);
        }

        PROCESS_MEMORY_COUNTERS processMemoryCounters;
        if (GetProcessMemoryInfo(processHandle, &processMemoryCounters, sizeof(processMemoryCounters)))
        {
            workingSetMegaBytes = static_cast<double>(processMemoryCounters.WorkingSetSize) / (1024.0 * 1024.0);
        }

        CloseHandle(processHandle);
    }

    if (processName.empty() && executablePath.empty())
    {
        json errorPayload;
        errorPayload["isSuccessful"] = false;
        errorPayload["status"] = "error";
        errorPayload["errorMessage"] = "Process not found: " + std::to_string(processIdentifier);
        return errorPayload;
    }

    json processObject;
    processObject["processIdentifier"] = processIdentifier;
    processObject["processName"] = processName;
    processObject["executablePath"] = executablePath.empty() ? nullptr : json(executablePath);
    processObject["workingSetMegaBytes"] = workingSetMegaBytes;
    processObject["is32BitProcess"] = is32BitProcess;
    processObject["architecture"] = is32BitProcess ? "x86" : "x64";

    json resultPayload;
    resultPayload["isSuccessful"] = true;
    resultPayload["status"] = "success";
    resultPayload["process"] = processObject;

    return resultPayload;
}

struct ModuleInformationRecord
{
    std::string moduleName;
    std::string modulePath;
    std::string moduleCategory;
    bool is64Bit;
};

json GetProcessModules(DWORD processIdentifier)
{
    EnableDebugPrivilege();

    const std::set<std::string> systemModules = {
        "ntdll.dll",     "kernel32.dll",  "kernelbase.dll", "user32.dll",  "gdi32.dll",
        "advapi32.dll",  "msvcrt.dll",    "ucrtbase.dll",   "combase.dll", "rpcrt4.dll",
        "sechost.dll",   "comctl32.dll",  "shell32.dll",    "shlwapi.dll", "win32u.dll",
        "gdi32full.dll", "msvcp_win.dll", "shcore.dll",     "uxtheme.dll", "wow64.dll",
        "wow64cpu.dll",  "wow64win.dll",  "crypt32.dll",    "bcrypt.dll",  "bcryptprimitives.dll",
        "sspicli.dll",   "cryptsp.dll",   "winhttp.dll",    "urlmon.dll",  "wininet.dll"};

    const std::set<std::string> gameModules = {
        "d3d8.dll",     "d3d9.dll",      "d3d10.dll",     "d3d11.dll",          "d3d12.dll",          "dxgi.dll",
        "opengl32.dll", "glu32.dll",     "ddraw.dll",     "d3dcompiler_43.dll", "d3dcompiler_47.dll", "dinput.dll",
        "dinput8.dll",  "xinput1_4.dll", "xinput1_3.dll", "xinput1_2.dll",      "xinput1_1.dll",      "xinput9_1_0.dll",
        "dsound.dll",   "xaudio2_9.dll", "xaudio2_8.dll", "xaudio2_7.dll",      "ws2_32.dll",         "winmm.dll",
        "version.dll",  "binkw32.dll",   "binkw64.dll",   "steam_api.dll",      "steam_api64.dll"};

    std::vector<ModuleInformationRecord> collectedModules;
    std::set<std::string> seenModuleNames;
    BOOL is32BitProcess = FALSE;

    std::string targetExecutablePath;
    std::string targetProcessName;

    HANDLE processLimitedHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processIdentifier);
    if (processLimitedHandle != NULL)
    {
        WCHAR fullPathBuffer[MAX_PATH];
        DWORD fullPathSize = MAX_PATH;
        if (QueryFullProcessImageNameW(processLimitedHandle, 0, fullPathBuffer, &fullPathSize))
        {
            targetExecutablePath = ConvertWideStringToUtf8(fullPathBuffer);
            std::filesystem::path resolvedExePath(fullPathBuffer);
            targetProcessName = ConvertWideStringToUtf8(resolvedExePath.filename().wstring());
        }
        IsWow64Process(processLimitedHandle, &is32BitProcess);
        CloseHandle(processLimitedHandle);
    }

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIdentifier);
    if (processHandle != NULL)
    {
        IsWow64Process(processHandle, &is32BitProcess);

        HMODULE moduleHandles[2048];
        DWORD bytesNeeded = 0;
        if (EnumProcessModulesEx(processHandle, moduleHandles, sizeof(moduleHandles), &bytesNeeded, LIST_MODULES_ALL))
        {
            DWORD moduleCount = bytesNeeded / sizeof(HMODULE);
            for (DWORD moduleIndex = 0; moduleIndex < moduleCount; moduleIndex++)
            {
                WCHAR moduleNameBuffer[MAX_PATH] = {0};
                WCHAR modulePathBuffer[MAX_PATH] = {0};
                if (GetModuleBaseNameW(processHandle, moduleHandles[moduleIndex], moduleNameBuffer, MAX_PATH) &&
                    GetModuleFileNameExW(processHandle, moduleHandles[moduleIndex], modulePathBuffer, MAX_PATH))
                {
                    MODULEINFO moduleInformation = {0};
                    GetModuleInformation(processHandle, moduleHandles[moduleIndex], &moduleInformation, sizeof(moduleInformation));

                    bool is64BitModule = (moduleInformation.lpBaseOfDll > (LPVOID)0x100000000);
                    if (is32BitProcess && is64BitModule)
                    {
                        continue;
                    }

                    std::string moduleName = ConvertWideStringToUtf8(moduleNameBuffer);
                    std::string modulePath = ConvertWideStringToUtf8(modulePathBuffer);
                    std::string lowerCaseModuleName = moduleName;
                    std::transform(lowerCaseModuleName.begin(), lowerCaseModuleName.end(), lowerCaseModuleName.begin(), ::tolower);

                    if (seenModuleNames.insert(lowerCaseModuleName).second)
                    {
                        std::string moduleCategory = "neutral";
                        if (systemModules.count(lowerCaseModuleName) > 0)
                        {
                            moduleCategory = "system";
                        }
                        else if (gameModules.count(lowerCaseModuleName) > 0)
                        {
                            moduleCategory = "good";
                        }

                        collectedModules.push_back({moduleName, modulePath, moduleCategory, is64BitModule});
                    }
                }
            }
        }
        CloseHandle(processHandle);
    }

    if (collectedModules.empty())
    {
        HANDLE moduleSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processIdentifier);
        if (moduleSnapshotHandle != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32W moduleEntry;
            moduleEntry.dwSize = sizeof(MODULEENTRY32W);
            if (Module32FirstW(moduleSnapshotHandle, &moduleEntry))
            {
                do
                {
                    std::string moduleName = ConvertWideStringToUtf8(moduleEntry.szModule);
                    std::string modulePath = ConvertWideStringToUtf8(moduleEntry.szExePath);
                    std::string lowerCaseModuleName = moduleName;
                    std::transform(lowerCaseModuleName.begin(), lowerCaseModuleName.end(), lowerCaseModuleName.begin(), ::tolower);

                    if (seenModuleNames.insert(lowerCaseModuleName).second)
                    {
                        std::string moduleCategory = "neutral";
                        if (systemModules.count(lowerCaseModuleName) > 0)
                        {
                            moduleCategory = "system";
                        }
                        else if (gameModules.count(lowerCaseModuleName) > 0)
                        {
                            moduleCategory = "good";
                        }

                        bool is64BitModule = ((uintptr_t)moduleEntry.modBaseAddr > 0x100000000ULL);
                        if (!(is32BitProcess && is64BitModule))
                        {
                            collectedModules.push_back({moduleName, modulePath, moduleCategory, is64BitModule});
                        }
                    }
                } while (Module32NextW(moduleSnapshotHandle, &moduleEntry));
            }
            CloseHandle(moduleSnapshotHandle);
        }
    }

    if (!targetExecutablePath.empty() && std::filesystem::exists(targetExecutablePath))
    {
        try
        {
            std::unique_ptr<LIEF::PE::Binary> parsedExecutableBinary = LIEF::PE::Parser::parse(targetExecutablePath);
            if (parsedExecutableBinary)
            {
                bool binaryIs32Bit = (parsedExecutableBinary->type() == LIEF::PE::PE_TYPE::PE32);
                if (collectedModules.empty())
                {
                    is32BitProcess = binaryIs32Bit ? TRUE : FALSE;
                }

                std::filesystem::path executableDirectory = std::filesystem::path(targetExecutablePath).parent_path();
                std::filesystem::path system32Directory = "C:\\Windows\\System32";
                std::filesystem::path sysWow64Directory = "C:\\Windows\\SysWOW64";
                std::filesystem::path systemDirectory = is32BitProcess ? sysWow64Directory : system32Directory;

                auto resolveDllPath = [&](const std::string &candidateDllName) -> std::string {
                    std::filesystem::path localCandidate = executableDirectory / candidateDllName;
                    if (std::filesystem::exists(localCandidate))
                    {
                        return localCandidate.string();
                    }

                    std::filesystem::path systemCandidate = systemDirectory / candidateDllName;
                    if (std::filesystem::exists(systemCandidate))
                    {
                        return systemCandidate.string();
                    }

                    std::filesystem::path system32Candidate = system32Directory / candidateDllName;
                    if (std::filesystem::exists(system32Candidate))
                    {
                        return system32Candidate.string();
                    }

                    std::filesystem::path windowsCandidate = std::filesystem::path("C:\\Windows") / candidateDllName;
                    if (std::filesystem::exists(windowsCandidate))
                    {
                        return windowsCandidate.string();
                    }

                    return localCandidate.string();
                };

                auto registerModuleCandidate = [&](const std::string &rawDllName) {
                    if (rawDllName.empty())
                    {
                        return;
                    }

                    std::string lowerCaseModuleName = rawDllName;
                    std::transform(lowerCaseModuleName.begin(), lowerCaseModuleName.end(), lowerCaseModuleName.begin(), ::tolower);

                    if (seenModuleNames.insert(lowerCaseModuleName).second)
                    {
                        std::string resolvedPath = resolveDllPath(rawDllName);
                        std::string moduleCategory = "neutral";
                        if (systemModules.count(lowerCaseModuleName) > 0)
                        {
                            moduleCategory = "system";
                        }
                        else if (gameModules.count(lowerCaseModuleName) > 0)
                        {
                            moduleCategory = "good";
                        }

                        collectedModules.push_back({rawDllName, resolvedPath, moduleCategory, !is32BitProcess});
                    }
                };

                for (const LIEF::PE::Import &importEntry : parsedExecutableBinary->imports())
                {
                    registerModuleCandidate(importEntry.name());
                }

                if (parsedExecutableBinary->has_delay_imports())
                {
                    for (const LIEF::PE::DelayImport &delayImportEntry : parsedExecutableBinary->delay_imports())
                    {
                        registerModuleCandidate(delayImportEntry.name());
                    }
                }

                try
                {
                    for (const auto &directoryEntry : std::filesystem::directory_iterator(executableDirectory))
                    {
                        if (directoryEntry.is_regular_file())
                        {
                            std::string extensionString = directoryEntry.path().extension().string();
                            std::transform(extensionString.begin(), extensionString.end(), extensionString.begin(), ::tolower);
                            if (extensionString == ".dll")
                            {
                                std::string localDllName = directoryEntry.path().filename().string();
                                std::string localDllPath = directoryEntry.path().string();
                                std::string lowerCaseModuleName = localDllName;
                                std::transform(lowerCaseModuleName.begin(), lowerCaseModuleName.end(), lowerCaseModuleName.begin(), ::tolower);

                                if (seenModuleNames.insert(lowerCaseModuleName).second)
                                {
                                    std::string moduleCategory = "neutral";
                                    if (systemModules.count(lowerCaseModuleName) > 0)
                                    {
                                        moduleCategory = "system";
                                    }
                                    else if (gameModules.count(lowerCaseModuleName) > 0)
                                    {
                                        moduleCategory = "good";
                                    }

                                    collectedModules.push_back({localDllName, localDllPath, moduleCategory, !is32BitProcess});
                                }
                            }
                        }
                    }
                }
                catch (const std::exception &)
                {
                }
            }
        }
        catch (const std::exception &)
        {
        }
    }

    std::sort(collectedModules.begin(), collectedModules.end(), [](const ModuleInformationRecord &firstItem, const ModuleInformationRecord &secondItem) {
        auto getCategoryRank = [](const std::string &category) -> int {
            if (category == "good") return 0;
            if (category == "neutral") return 1;
            return 2;
        };
        int firstRank = getCategoryRank(firstItem.moduleCategory);
        int secondRank = getCategoryRank(secondItem.moduleCategory);
        if (firstRank != secondRank)
        {
            return firstRank < secondRank;
        }
        return firstItem.moduleName < secondItem.moduleName;
    });

    bool hasFoundFirstSelectableModule = false;
    json modulesJsonArray = json::array();
    for (const auto &moduleItem : collectedModules)
    {
        bool isSelectable = (moduleItem.moduleCategory != "system");
        bool isSelected = false;
        if (isSelectable && !hasFoundFirstSelectableModule)
        {
            isSelected = true;
            hasFoundFirstSelectableModule = true;
        }

        json moduleObject;
        moduleObject["name"] = moduleItem.moduleName;
        moduleObject["path"] = moduleItem.modulePath;
        moduleObject["selected"] = isSelected;
        moduleObject["category"] = moduleItem.moduleCategory;
        moduleObject["isProxyable"] = isSelectable;
        moduleObject["is64BitModule"] = moduleItem.is64Bit;
        modulesJsonArray.push_back(moduleObject);
    }

    json processInfoObject;
    processInfoObject["processIdentifier"] = processIdentifier;
    processInfoObject["processName"] = targetProcessName;
    processInfoObject["executablePath"] = targetExecutablePath.empty() ? nullptr : json(targetExecutablePath);
    processInfoObject["is32BitProcess"] = is32BitProcess ? true : false;
    processInfoObject["architecture"] = is32BitProcess ? "x86" : "x64";

    json resultPayload;
    resultPayload["isSuccessful"] = true;
    resultPayload["status"] = "success";
    resultPayload["targetProcess"] = processInfoObject;
    resultPayload["is32BitProcess"] = is32BitProcess ? true : false;
    resultPayload["totalModulesCount"] = collectedModules.size();
    resultPayload["modules"] = modulesJsonArray;

    return resultPayload;
}

json GetDllExports(const std::string &dllFilePath)
{
    std::string sanitizedFilePath = dllFilePath;
    size_t currentPosition = 0;
    while ((currentPosition = sanitizedFilePath.find("\\\\", currentPosition)) != std::string::npos)
    {
        sanitizedFilePath.replace(currentPosition, 2, "\\");
        currentPosition += 1;
    }

    if (!std::filesystem::exists(sanitizedFilePath))
    {
        json errorPayload;
        errorPayload["isSuccessful"] = false;
        errorPayload["status"] = "error";
        errorPayload["errorMessage"] = "DLL file not found: " + sanitizedFilePath;
        errorPayload["filePath"] = sanitizedFilePath;
        return errorPayload;
    }

    try
    {
        std::unique_ptr<LIEF::PE::Binary> parsedBinary = LIEF::PE::Parser::parse(sanitizedFilePath);
        if (!parsedBinary)
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "Failed to parse PE headers for: " + sanitizedFilePath;
            return errorPayload;
        }

        bool is64Bit = (parsedBinary->type() == LIEF::PE::PE_TYPE::PE32_PLUS);
        std::string architectureString = is64Bit ? "x64" : "x86";
        std::string baseFileName = std::filesystem::path(sanitizedFilePath).filename().string();

        json exportedFunctionsArray = json::array();

        if (parsedBinary->has_exports())
        {
            for (const LIEF::PE::ExportEntry &exportEntry : parsedBinary->get_export()->entries())
            {
                std::string functionName = exportEntry.name();
                if (functionName.empty())
                {
                    functionName = "ordinal_" + std::to_string(exportEntry.ordinal());
                }

                json functionObject;
                functionObject["name"] = functionName;
                functionObject["ordinal"] = exportEntry.ordinal();
                functionObject["relativeVirtualAddress"] = exportEntry.address();
                functionObject["isForwarded"] = exportEntry.is_forwarded();
                functionObject["forwarderName"] = exportEntry.is_forwarded() ? exportEntry.forward_information().function : "";
                functionObject["module"] = baseFileName;
                functionObject["type"] = "Export";
                functionObject["parameters"] = "(...)";

                exportedFunctionsArray.push_back(functionObject);
            }
        }

        json resultPayload;
        resultPayload["isSuccessful"] = true;
        resultPayload["status"] = "success";
        resultPayload["filePath"] = sanitizedFilePath;
        resultPayload["fileName"] = baseFileName;
        resultPayload["architecture"] = architectureString;
        resultPayload["is64BitArchitecture"] = is64Bit;
        resultPayload["totalExportsCount"] = exportedFunctionsArray.size();
        resultPayload["exportedFunctions"] = exportedFunctionsArray;

        return resultPayload;
    }
    catch (const std::exception &exceptionDetails)
    {
        json errorPayload;
        errorPayload["isSuccessful"] = false;
        errorPayload["status"] = "error";
        errorPayload["errorMessage"] = std::string("Exception parsing PE exports: ") + exceptionDetails.what();
        errorPayload["filePath"] = sanitizedFilePath;
        return errorPayload;
    }
}

json AnalyzeProxyCandidates(DWORD processIdentifier)
{
    json modulesResult = GetProcessModules(processIdentifier);
    if (!modulesResult["isSuccessful"].get<bool>())
    {
        return modulesResult;
    }

    bool is32BitProcess = modulesResult["is32BitProcess"].get<bool>();
    json candidateList = json::array();
    std::string bestRecommendationName;
    int highestScore = -1;

    for (const auto &moduleItem : modulesResult["modules"])
    {
        std::string category = moduleItem["category"].get<std::string>();
        if (category == "system")
        {
            continue;
        }

        std::string moduleName = moduleItem["name"].get<std::string>();
        std::string modulePath = moduleItem["path"].get<std::string>();

        json exportsResult = GetDllExports(modulePath);
        int exportsCount = 0;
        json sampleFunctions = json::array();

        if (exportsResult["isSuccessful"].get<bool>())
        {
            exportsCount = exportsResult["totalExportsCount"].get<int>();
            const auto &allExports = exportsResult["exportedFunctions"];
            size_t sampleLimit = std::min(static_cast<size_t>(10), allExports.size());
            for (size_t index = 0; index < sampleLimit; ++index)
            {
                sampleFunctions.push_back(allExports[index]["name"].get<std::string>());
            }
        }

        int score = 50;
        std::string rationale;

        std::string lowerModuleName = moduleName;
        std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::tolower);

        if (lowerModuleName == "dinput8.dll" || lowerModuleName == "version.dll" || lowerModuleName == "dxgi.dll")
        {
            score = 100;
            rationale = "Gold standard proxy target with early process initialization and standard export layout.";
        }
        else if (lowerModuleName == "d3d11.dll" || lowerModuleName == "xinput1_3.dll" || lowerModuleName == "xinput1_4.dll" || lowerModuleName == "d3d9.dll")
        {
            score = 90;
            rationale = "Excellent graphics/input proxy target widely supported across Windows games.";
        }
        else if (lowerModuleName == "steam_api64.dll" || lowerModuleName == "steam_api.dll" || lowerModuleName == "binkw64.dll" || lowerModuleName == "binkw32.dll")
        {
            score = 85;
            rationale = "Local third-party game middleware DLL with direct local directory loading.";
        }
        else if (category == "good")
        {
            score = 80;
            rationale = "Recognized multimedia or game runtime DLL suitable for proxy hijacking.";
        }
        else
        {
            score = 65;
            rationale = "Local application module suitable for custom hooking and payload execution.";
        }

        if (score > highestScore)
        {
            highestScore = score;
            bestRecommendationName = moduleName;
        }

        json candidateObject;
        candidateObject["moduleName"] = moduleName;
        candidateObject["modulePath"] = modulePath;
        candidateObject["category"] = category;
        candidateObject["suitabilityScore"] = score;
        candidateObject["rationale"] = rationale;
        candidateObject["totalExportsCount"] = exportsCount;
        candidateObject["sampleExportedFunctions"] = sampleFunctions;

        candidateList.push_back(candidateObject);
    }

    std::sort(candidateList.begin(), candidateList.end(), [](const json &firstItem, const json &secondItem) {
        return firstItem["suitabilityScore"].get<int>() > secondItem["suitabilityScore"].get<int>();
    });

    json resultPayload;
    resultPayload["isSuccessful"] = true;
    resultPayload["status"] = "success";
    resultPayload["targetProcess"] = modulesResult["targetProcess"];
    resultPayload["bestRecommendation"] = bestRecommendationName;
    resultPayload["totalCandidatesFound"] = candidateList.size();
    resultPayload["candidates"] = candidateList;

    return resultPayload;
}

json GenerateProxyProject(const json &projectOptions)
{
    try
    {
        std::string projectName = projectOptions.value("projectName", "MyProxyProject");
        std::string outputDirectoryString = projectOptions.value("outputDir", projectOptions.value("outputDirectoryPath", ""));
        std::string targetModulePathString = projectOptions.value("targetDllPath", projectOptions.value("targetModulePath", ""));

        if (projectName.empty() || outputDirectoryString.empty() || targetModulePathString.empty())
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "projectName, outputDir, and targetDllPath are all required.";
            return errorPayload;
        }

        std::filesystem::path outputDirectory(outputDirectoryString);
        std::filesystem::path targetModulePath(targetModulePathString);

        if (!std::filesystem::exists(targetModulePath))
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "Target DLL file does not exist: " + targetModulePathString;
            return errorPayload;
        }

        std::filesystem::create_directories(outputDirectory);

        auto targetDllBinary = LIEF::PE::Parser::parse(targetModulePath.string());
        if (!targetDllBinary || !targetDllBinary->has_exports())
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "Could not parse PE exports from target DLL: " + targetModulePathString;
            return errorPayload;
        }

        bool is64BitProcess = (targetDllBinary->type() == LIEF::PE::PE_TYPE::PE32_PLUS);
        if (projectOptions.contains("isTargetProcess32Bit"))
        {
            is64BitProcess = !projectOptions["isTargetProcess32Bit"].get<bool>();
        }
        else if (projectOptions.contains("is64BitArchitecture"))
        {
            is64BitProcess = projectOptions["is64BitArchitecture"].get<bool>();
        }

        std::set<std::string> chosenFunctionNames;
        if (projectOptions.contains("functions") && projectOptions["functions"].is_array())
        {
            for (const auto &functionNode : projectOptions["functions"])
            {
                if (functionNode.is_object() && functionNode.contains("name"))
                {
                    chosenFunctionNames.insert(functionNode["name"].get<std::string>());
                }
                else if (functionNode.is_string())
                {
                    chosenFunctionNames.insert(functionNode.get<std::string>());
                }
            }
        }
        else if (projectOptions.contains("selectedFunctionNames") && projectOptions["selectedFunctionNames"].is_array())
        {
            for (const auto &functionNode : projectOptions["selectedFunctionNames"])
            {
                chosenFunctionNames.insert(functionNode.get<std::string>());
            }
        }

        struct ExportInformation
        {
            std::string codeName;
            LIEF::PE::ExportEntry entryData;
        };

        std::vector<ExportInformation> selectedExportsList;
        for (const LIEF::PE::ExportEntry &exportEntry : targetDllBinary->get_export()->entries())
        {
            std::string codeName = exportEntry.name();
            if (codeName.empty())
            {
                codeName = "ordinal_" + std::to_string(exportEntry.ordinal());
            }

            if (chosenFunctionNames.empty() || chosenFunctionNames.count(codeName) > 0)
            {
                selectedExportsList.push_back({codeName, exportEntry});
            }
        }

        if (selectedExportsList.empty())
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "No exported functions selected or found in target DLL.";
            return errorPayload;
        }

        std::ofstream cmakeBuildFile(outputDirectory / "CMakeLists.txt");
        cmakeBuildFile << "cmake_minimum_required(VERSION 3.15)\n"
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
                       << "endif()\n";
        cmakeBuildFile.close();

        std::ofstream moduleDefinitionFile(outputDirectory / (projectName + ".def"));
        moduleDefinitionFile << "LIBRARY " << projectName << "\n";
        moduleDefinitionFile << "EXPORTS\n";
        for (const auto &exportInfo : selectedExportsList)
        {
            moduleDefinitionFile << "    " << exportInfo.codeName << " @" << exportInfo.entryData.ordinal() << "\n";
        }
        moduleDefinitionFile.close();

        std::ofstream proxyHeaderFile(outputDirectory / "proxy.h");
        proxyHeaderFile << "#pragma once\n"
                        << "#include <windows.h>\n\n"
                        << "extern \"C\" {\n";
        for (const auto &exportInfo : selectedExportsList)
        {
            proxyHeaderFile << "    extern FARPROC pfn" << exportInfo.codeName << ";\n";
        }
        proxyHeaderFile << "}\n";
        proxyHeaderFile.close();

        std::string originalModuleName = targetModulePath.stem().string() + "_original.dll";
        if (projectOptions.contains("originalDllNameOverride") && !projectOptions["originalDllNameOverride"].get<std::string>().empty())
        {
            originalModuleName = projectOptions["originalDllNameOverride"].get<std::string>();
        }

        bool enableDebugConsole = projectOptions.value("enableDebugConsole", true);
        std::string customPayloadCode = projectOptions.value("customPayloadCode", "");

        std::ofstream dllMainSourceFile(outputDirectory / "dllmain.cpp");
        dllMainSourceFile << "#include \"proxy.h\"\n"
                          << "#include <string>\n"
                          << "#include <iostream>\n\n"
                          << "HMODULE hOriginalDll = NULL;\n"
                          << "const std::string originalDllName = \"" << originalModuleName << "\";\n\n";

        if (enableDebugConsole)
        {
            dllMainSourceFile << "void SpawnDebugConsole() {\n"
                              << "    if (AllocConsole()) {\n"
                              << "        FILE* pConsoleOutput;\n"
                              << "        freopen_s(&pConsoleOutput, \"CONOUT$\", \"w\", stdout);\n"
                              << "        freopen_s(&pConsoleOutput, \"CONOUT$\", \"w\", stderr);\n"
                              << "        SetConsoleTitleA(\"" << projectName << " - Debug Console\");\n"
                              << "        std::cout << \"[" << projectName << "] Proxy loaded successfully!\" << std::endl;\n"
                              << "    }\n"
                              << "}\n\n";
        }

        if (!customPayloadCode.empty())
        {
            dllMainSourceFile << "void ExecuteCustomPayload() {\n"
                              << "    " << customPayloadCode << "\n"
                              << "}\n\n";
        }

        dllMainSourceFile << "extern \"C\" {\n";
        for (const auto &exportInfo : selectedExportsList)
        {
            dllMainSourceFile << "    FARPROC pfn" << exportInfo.codeName << " = NULL;\n";
        }
        dllMainSourceFile << "}\n\n"
                          << "void InitializeProxies(HMODULE hMod) {\n";

        for (const auto &exportInfo : selectedExportsList)
        {
            if (exportInfo.entryData.name().empty())
            {
                dllMainSourceFile << "    pfn" << exportInfo.codeName << " = GetProcAddress(hMod, MAKEINTRESOURCEA("
                                  << exportInfo.entryData.ordinal() << "));\n";
            }
            else
            {
                dllMainSourceFile << "    pfn" << exportInfo.codeName << " = GetProcAddress(hMod, \""
                                  << exportInfo.entryData.name() << "\");\n";
            }
        }
        dllMainSourceFile << "}\n\n"
                          << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n"
                          << "    switch (ul_reason_for_call) {\n"
                          << "        case DLL_PROCESS_ATTACH:\n"
                          << "            DisableThreadLibraryCalls(hModule);\n";

        if (enableDebugConsole)
        {
            dllMainSourceFile << "            SpawnDebugConsole();\n";
        }
        if (!customPayloadCode.empty())
        {
            dllMainSourceFile << "            ExecuteCustomPayload();\n";
        }

        dllMainSourceFile << "            hOriginalDll = LoadLibraryA(originalDllName.c_str());\n"
                          << "            if (hOriginalDll) {\n"
                          << "                InitializeProxies(hOriginalDll);\n"
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
                          << "}\n";
        dllMainSourceFile.close();

        std::ofstream proxyAssemblyFile(outputDirectory / "proxy.asm");
        if (is64BitProcess)
        {
            proxyAssemblyFile << ".CODE\n\n";
            for (const auto &exportInfo : selectedExportsList)
            {
                proxyAssemblyFile << "EXTERN pfn" << exportInfo.codeName << ":QWORD\n";
            }
            proxyAssemblyFile << "\n";
            for (const auto &exportInfo : selectedExportsList)
            {
                proxyAssemblyFile << "PUBLIC " << exportInfo.codeName << "\n"
                                  << exportInfo.codeName << " PROC\n"
                                  << "    jmp qword ptr [pfn" << exportInfo.codeName << "]\n"
                                  << exportInfo.codeName << " ENDP\n\n";
            }
        }
        else
        {
            proxyAssemblyFile << ".MODEL FLAT, C\n\n.CODE\n\n";
            for (const auto &exportInfo : selectedExportsList)
            {
                proxyAssemblyFile << "EXTERN pfn" << exportInfo.codeName << ":DWORD\n";
            }
            proxyAssemblyFile << "\n";
            for (const auto &exportInfo : selectedExportsList)
            {
                proxyAssemblyFile << "PUBLIC " << exportInfo.codeName << "\n"
                                  << exportInfo.codeName << " PROC\n"
                                  << "    jmp dword ptr [pfn" << exportInfo.codeName << "]\n"
                                  << exportInfo.codeName << " ENDP\n\n";
            }
        }
        proxyAssemblyFile << "END\n";
        proxyAssemblyFile.close();

        std::vector<std::string> generatedFilesList = {
            "CMakeLists.txt",
            projectName + ".def",
            "proxy.h",
            "dllmain.cpp",
            "proxy.asm"
        };

        json resultPayload;
        resultPayload["isSuccessful"] = true;
        resultPayload["status"] = "success";
        resultPayload["projectName"] = projectName;
        resultPayload["outputDirectoryPath"] = outputDirectoryString;
        resultPayload["targetModulePath"] = targetModulePathString;
        resultPayload["originalDllFileName"] = originalModuleName;
        resultPayload["is64BitArchitecture"] = is64BitProcess;
        resultPayload["totalExportedFunctionsCount"] = selectedExportsList.size();
        resultPayload["generatedFiles"] = generatedFilesList;
        resultPayload["buildInstructions"] = "cmake -B build -A " + std::string(is64BitProcess ? "x64" : "Win32") + " && cmake --build build --config Release";

        return resultPayload;
    }
    catch (const std::exception &exceptionDetails)
    {
        json errorPayload;
        errorPayload["isSuccessful"] = false;
        errorPayload["status"] = "error";
        errorPayload["errorMessage"] = std::string("Failed to generate proxy project: ") + exceptionDetails.what();
        return errorPayload;
    }
}

json BuildProxyProject(const std::string &projectDirectoryPath, const std::string &buildConfiguration)
{
    std::filesystem::path projectPath(projectDirectoryPath);
    if (!std::filesystem::exists(projectPath / "CMakeLists.txt"))
    {
        json errorPayload;
        errorPayload["isSuccessful"] = false;
        errorPayload["status"] = "error";
        errorPayload["errorMessage"] = "CMakeLists.txt not found in directory: " + projectDirectoryPath;
        return errorPayload;
    }

    std::string configName = buildConfiguration.empty() ? "Release" : buildConfiguration;
    std::string commandString = "cmake -B \"" + (projectPath / "build").string() + "\" -S \"" + projectPath.string() + "\" && cmake --build \"" + (projectPath / "build").string() + "\" --config " + configName;

    std::string buildOutput;
    FILE *pipeHandle = _popen(commandString.c_str(), "r");
    if (!pipeHandle)
    {
        json errorPayload;
        errorPayload["isSuccessful"] = false;
        errorPayload["status"] = "error";
        errorPayload["errorMessage"] = "Failed to spawn CMake build process";
        return errorPayload;
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), pipeHandle) != NULL)
    {
        buildOutput += buffer;
    }

    int exitCode = _pclose(pipeHandle);

    if (exitCode != 0)
    {
        json errorPayload;
        errorPayload["isSuccessful"] = false;
        errorPayload["status"] = "error";
        errorPayload["errorMessage"] = "CMake build failed with exit code: " + std::to_string(exitCode);
        errorPayload["buildOutput"] = buildOutput;
        return errorPayload;
    }

    json resultPayload;
    resultPayload["isSuccessful"] = true;
    resultPayload["status"] = "success";
    resultPayload["buildFolderPath"] = (projectPath / "build" / configName).string();
    resultPayload["buildOutput"] = buildOutput;

    return resultPayload;
}
