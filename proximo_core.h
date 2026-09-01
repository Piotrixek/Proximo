#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include "json.hpp"

using json = nlohmann::json;

void EnableDebugPrivilege();

std::string ConvertWideStringToUtf8(const std::wstring &wideString);

DWORD FindProcessIdentifierByNameOrString(const std::string &identifierOrName);

json GetRunningProcesses(const std::string &filterQuery = "");

json GetProcessDetails(DWORD processIdentifier);

json GetProcessModules(DWORD processIdentifier);

json GetDllExports(const std::string &dllFilePath);

json AnalyzeProxyCandidates(DWORD processIdentifier);

json GenerateProxyProject(const json &projectOptions);

json BuildProxyProject(const std::string &projectDirectoryPath, const std::string &buildConfiguration = "Release");
