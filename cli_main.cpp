#include "proximo_core.h"
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <LIEF/logging.hpp>

int main(int argc, char **argv)
{
    LIEF::logging::disable();
    EnableDebugPrivilege();

    if (argc < 2)
    {
        json errorPayload;
        errorPayload["isSuccessful"] = false;
        errorPayload["status"] = "error";
        errorPayload["errorMessage"] = "No command specified. Available commands: list-processes, get-process-details, list-modules, get-exports, analyze-candidates, generate-proxy, build-proxy";
        std::cout << errorPayload.dump() << std::endl;
        return 1;
    }

    std::string commandName = argv[1];

    if (commandName == "list-processes")
    {
        std::string filterQuery = (argc >= 3) ? argv[2] : "";
        json resultPayload = GetRunningProcesses(filterQuery);
        std::cout << resultPayload.dump() << std::endl;
        return 0;
    }
    else if (commandName == "get-process-details")
    {
        if (argc < 3)
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "Missing target process identifier or name";
            std::cout << errorPayload.dump() << std::endl;
            return 1;
        }
        DWORD processIdentifier = FindProcessIdentifierByNameOrString(argv[2]);
        json resultPayload = GetProcessDetails(processIdentifier);
        std::cout << resultPayload.dump() << std::endl;
        return 0;
    }
    else if (commandName == "list-modules")
    {
        if (argc < 3)
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "Missing target process identifier or name";
            std::cout << errorPayload.dump() << std::endl;
            return 1;
        }
        DWORD processIdentifier = FindProcessIdentifierByNameOrString(argv[2]);
        json resultPayload = GetProcessModules(processIdentifier);
        std::cout << resultPayload.dump() << std::endl;
        return 0;
    }
    else if (commandName == "get-exports")
    {
        if (argc < 3)
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "Missing target DLL file path";
            std::cout << errorPayload.dump() << std::endl;
            return 1;
        }
        json resultPayload = GetDllExports(argv[2]);
        std::cout << resultPayload.dump() << std::endl;
        return 0;
    }
    else if (commandName == "analyze-candidates")
    {
        if (argc < 3)
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "Missing target process identifier or name";
            std::cout << errorPayload.dump() << std::endl;
            return 1;
        }
        DWORD processIdentifier = FindProcessIdentifierByNameOrString(argv[2]);
        json resultPayload = AnalyzeProxyCandidates(processIdentifier);
        std::cout << resultPayload.dump() << std::endl;
        return 0;
    }
    else if (commandName == "generate-proxy")
    {
        if (argc < 3)
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "Missing project options JSON string or file path";
            std::cout << errorPayload.dump() << std::endl;
            return 1;
        }

        std::string rawArgument = argv[2];
        json parsedOptions;
        try
        {
            if (std::filesystem::exists(rawArgument))
            {
                std::ifstream fileStream(rawArgument);
                fileStream >> parsedOptions;
            }
            else
            {
                parsedOptions = json::parse(rawArgument);
            }
        }
        catch (const std::exception &exceptionDetails)
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = std::string("JSON parse error: ") + exceptionDetails.what();
            std::cout << errorPayload.dump() << std::endl;
            return 1;
        }

        json resultPayload = GenerateProxyProject(parsedOptions);
        std::cout << resultPayload.dump() << std::endl;
        return 0;
    }
    else if (commandName == "build-proxy")
    {
        if (argc < 3)
        {
            json errorPayload;
            errorPayload["isSuccessful"] = false;
            errorPayload["status"] = "error";
            errorPayload["errorMessage"] = "Missing target project directory path";
            std::cout << errorPayload.dump() << std::endl;
            return 1;
        }
        std::string buildConfiguration = (argc >= 4) ? argv[3] : "Release";
        json resultPayload = BuildProxyProject(argv[2], buildConfiguration);
        std::cout << resultPayload.dump() << std::endl;
        return 0;
    }
    else
    {
        json errorPayload;
        errorPayload["isSuccessful"] = false;
        errorPayload["status"] = "error";
        errorPayload["errorMessage"] = "Unknown command: " + commandName;
        std::cout << errorPayload.dump() << std::endl;
        return 1;
    }
}
