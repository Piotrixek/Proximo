import { execFile } from "child_process";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));

function resolveProximoCliExecutablePath() {
    const candidatePaths = [
        path.resolve(currentDirectory, "../Build/Release/proximo_cli.exe"),
        path.resolve(currentDirectory, "../Build/Debug/proximo_cli.exe"),
        path.resolve(currentDirectory, "../Build/proximo_cli.exe"),
        path.resolve(currentDirectory, "../../Build/Release/proximo_cli.exe"),
        "C:\\Users\\User\\OneDrive\\Desktop\\C O D I N G\\Proximo\\Build\\Release\\proximo_cli.exe"
    ];

    for (const singleCandidatePath of candidatePaths) {
        if (fs.existsSync(singleCandidatePath)) {
            return singleCandidatePath;
        }
    }

    return "proximo_cli.exe";
}

export function executeProximoCoreCommand(commandArguments) {
    return new Promise((resolve) => {
        const executablePath = resolveProximoCliExecutablePath();
        execFile(executablePath, commandArguments, { maxBuffer: 1024 * 1024 * 64 }, (errorDetails, standardOutput, standardError) => {
            if (errorDetails && !standardOutput) {
                return resolve({
                    isSuccessful: false,
                    status: "error",
                    errorMessage: errorDetails.message + (standardError ? " | " + standardError : "")
                });
            }

            try {
                const parsedOutput = JSON.parse(standardOutput.trim());
                return resolve(parsedOutput);
            } catch (jsonParseException) {
                return resolve({
                    isSuccessful: false,
                    status: "error",
                    errorMessage: "Failed to parse JSON output from proximo C++ engine: " + jsonParseException.message,
                    rawOutput: standardOutput
                });
            }
        });
    });
}

export async function enumerateRunningProcesses(filterQuery = "") {
    return await executeProximoCoreCommand(["list-processes", filterQuery]);
}

export async function findProcessByIdentifierOrName(processIdentifierOrName) {
    return await executeProximoCoreCommand(["get-process-details", String(processIdentifierOrName)]);
}

export async function enumerateProcessModules(processIdentifierOrName) {
    return await executeProximoCoreCommand(["list-modules", String(processIdentifierOrName)]);
}

export async function parsePeExports(dllFilePath) {
    return await executeProximoCoreCommand(["get-exports", dllFilePath]);
}

export async function analyzeProxyCandidatesForProcess(processIdentifierOrName) {
    return await executeProximoCoreCommand(["analyze-candidates", String(processIdentifierOrName)]);
}

export async function generateProxyProjectFiles(projectOptions) {
    const jsonOptionsString = JSON.stringify(projectOptions);
    return await executeProximoCoreCommand(["generate-proxy", jsonOptionsString]);
}

export async function buildProxyProject(projectDirectoryPath, buildConfiguration = "Release") {
    return await executeProximoCoreCommand(["build-proxy", projectDirectoryPath, buildConfiguration]);
}
