import { exec } from "child_process";
import util from "util";
import path from "path";
import fs from "fs";
import { parsePeExports } from "./pe_parser.js";

const executeCommandAsync = util.promisify(exec);

const KNOWN_SYSTEM_MODULES = new Set([
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "msvcrt.dll",
    "ucrtbase.dll",
    "combase.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "comctl32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "win32u.dll",
    "gdi32full.dll",
    "msvcp_win.dll",
    "shcore.dll",
    "uxtheme.dll",
    "wow64.dll",
    "wow64cpu.dll",
    "wow64win.dll",
    "crypt32.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "sspicli.dll",
    "cryptsp.dll",
    "winhttp.dll",
    "urlmon.dll",
    "wininet.dll"
]);

const RECOMMENDED_PROXY_MODULES = new Map([
    ["dinput8.dll", { score: 98, reason: "Classic DirectX DirectInput8 hook. Extremely stable and ubiquitous in games." }],
    ["version.dll", { score: 95, reason: "Widely used hijacking target. Loaded early by most Windows apps and games." }],
    ["dxgi.dll", { score: 92, reason: "DirectX Graphics Infrastructure. Ideal for rendering hooks and modern D3D11/D3D12 games." }],
    ["d3d11.dll", { score: 90, reason: "Direct3D 11 runtime. Perfect for DirectX 11 games." }],
    ["d3d9.dll", { score: 90, reason: "Direct3D 9 runtime. Perfect for legacy and 32-bit/64-bit DX9 games." }],
    ["d3d12.dll", { score: 88, reason: "Direct3D 12 runtime. Good for modern DX12 titles." }],
    ["xinput1_4.dll", { score: 87, reason: "Standard Xbox controller input DLL on modern Windows." }],
    ["xinput1_3.dll", { score: 87, reason: "Legacy DirectX Xbox controller input DLL." }],
    ["xinput9_1_0.dll", { score: 85, reason: "Legacy common controller input DLL." }],
    ["winmm.dll", { score: 82, reason: "Windows Multimedia API. Loaded early by audio/timer systems." }],
    ["xaudio2_7.dll", { score: 80, reason: "DirectX XAudio2 audio engine." }],
    ["xaudio2_9.dll", { score: 80, reason: "DirectX XAudio2 modern audio engine." }],
    ["dsound.dll", { score: 78, reason: "DirectSound audio engine." }],
    ["dinput.dll", { score: 75, reason: "DirectInput legacy API." }],
    ["ddraw.dll", { score: 75, reason: "DirectDraw legacy 2D/3D API." }],
    ["steam_api64.dll", { score: 94, reason: "Steamworks 64-bit API. Local game DLL with straightforward exports." }],
    ["steam_api.dll", { score: 94, reason: "Steamworks 32-bit API. Local game DLL with straightforward exports." }],
    ["binkw64.dll", { score: 85, reason: "RAD Game Tools Bink Video 64-bit." }],
    ["binkw32.dll", { score: 85, reason: "RAD Game Tools Bink Video 32-bit." }]
]);

export async function enumerateRunningProcesses(filterQuery = "") {
    try {
        const powershellScript = `
            Get-Process | ForEach-Object {
                $processPath = ""
                try {
                    $processPath = $_.Path
                } catch {}
                [PSCustomObject]@{
                    ProcessIdentifier = $_.Id
                    ProcessName = $_.ProcessName
                    ExecutablePath = $processPath
                    WorkingSetMegaBytes = [Math]::Round($_.WorkingSet64 / 1MB, 2)
                    MainWindowTitle = $_.MainWindowTitle
                }
            } | ConvertTo-Json -Compress
        `;

        const encodedScript = Buffer.from(powershellScript, "utf16le").toString("base64");
        const executionResult = await executeCommandAsync(`powershell.exe -NoProfile -NonInteractive -EncodedCommand ${encodedScript}`, { maxBuffer: 10 * 1024 * 1024 });

        let parsedProcessList = [];
        const rawOutput = executionResult.stdout.trim();
        if (rawOutput) {
            const rawParsed = JSON.parse(rawOutput);
            parsedProcessList = Array.isArray(rawParsed) ? rawParsed : [rawParsed];
        }

        const normalizedFilter = filterQuery.toLowerCase().trim();
        const filteredProcessList = parsedProcessList
            .filter((processItem) => {
                if (!normalizedFilter) return true;
                const processNameMatches = processItem.ProcessName && processItem.ProcessName.toLowerCase().includes(normalizedFilter);
                const windowTitleMatches = processItem.MainWindowTitle && processItem.MainWindowTitle.toLowerCase().includes(normalizedFilter);
                const pathMatches = processItem.ExecutablePath && processItem.ExecutablePath.toLowerCase().includes(normalizedFilter);
                const pidMatches = String(processItem.ProcessIdentifier).includes(normalizedFilter);
                return processNameMatches || windowTitleMatches || pathMatches || pidMatches;
            })
            .map((processItem) => ({
                processIdentifier: processItem.ProcessIdentifier,
                processName: processItem.ProcessName,
                executablePath: processItem.ExecutablePath || null,
                workingSetMegaBytes: processItem.WorkingSetMegaBytes,
                mainWindowTitle: processItem.MainWindowTitle || null
            }))
            .sort((firstItem, secondItem) => firstItem.processName.localeCompare(secondItem.processName));

        return {
            isSuccessful: true,
            totalFoundCount: filteredProcessList.length,
            processes: filteredProcessList
        };
    } catch (error) {
        return {
            isSuccessful: false,
            errorMessage: "Failed to enumerate running processes: " + error.message,
            totalFoundCount: 0,
            processes: []
        };
    }
}

export async function findProcessByIdentifierOrName(targetIdentifierOrName) {
    try {
        let processIdentifier = null;
        const targetString = String(targetIdentifierOrName).trim();

        if (/^\d+$/.test(targetString)) {
            processIdentifier = parseInt(targetString, 10);
        }

        const powershellScript = processIdentifier !== null
            ? `Get-Process -Id ${processIdentifier} | Select-Object -Property Id, ProcessName, Path, WorkingSet64, MainWindowTitle, Description | ConvertTo-Json -Compress`
            : `Get-Process -Name "${targetString.replace(/\.exe$/i, "")}" -ErrorAction SilentlyContinue | Select-Object -Property Id, ProcessName, Path, WorkingSet64, MainWindowTitle, Description | ConvertTo-Json -Compress`;

        const encodedScript = Buffer.from(powershellScript, "utf16le").toString("base64");
        const executionResult = await executeCommandAsync(`powershell.exe -NoProfile -NonInteractive -EncodedCommand ${encodedScript}`);

        const rawOutput = executionResult.stdout.trim();
        if (!rawOutput) {
            return {
                isSuccessful: false,
                errorMessage: `Process not found: ${targetIdentifierOrName}`,
                process: null
            };
        }

        const parsedOutput = JSON.parse(rawOutput);
        const processData = Array.isArray(parsedOutput) ? parsedOutput[0] : parsedOutput;

        let is64BitProcess = true;
        let mainModuleArchitecture = "x64";
        if (processData.Path && fs.existsSync(processData.Path)) {
            const peInspection = parsePeExports(processData.Path);
            if (peInspection.isSuccessful) {
                is64BitProcess = peInspection.is64BitArchitecture;
                mainModuleArchitecture = peInspection.architecture;
            }
        }

        return {
            isSuccessful: true,
            process: {
                processIdentifier: processData.Id,
                processName: processData.ProcessName,
                executablePath: processData.Path || null,
                workingSetMegaBytes: processData.WorkingSet64 ? Math.round((processData.WorkingSet64 / (1024 * 1024)) * 100) / 100 : null,
                mainWindowTitle: processData.MainWindowTitle || null,
                description: processData.Description || null,
                architecture: mainModuleArchitecture,
                is64BitProcess: is64BitProcess
            }
        };
    } catch (error) {
        return {
            isSuccessful: false,
            errorMessage: `Failed to find process: ${error.message}`,
            process: null
        };
    }
}

export async function enumerateProcessModules(targetIdentifierOrName) {
    try {
        const processLookupResult = await findProcessByIdentifierOrName(targetIdentifierOrName);
        if (!processLookupResult.isSuccessful || !processLookupResult.process) {
            return {
                isSuccessful: false,
                errorMessage: processLookupResult.errorMessage || "Process not found",
                modules: []
            };
        }

        const targetProcess = processLookupResult.process;
        const targetProcessIdentifier = targetProcess.processIdentifier;
        const targetExecutableDirectory = targetProcess.executablePath ? path.dirname(targetProcess.executablePath).toLowerCase() : "";

        const powershellScript = `
            try {
                $process = Get-Process -Id ${targetProcessIdentifier} -ErrorAction Stop
                $modules = $process.Modules | ForEach-Object {
                    [PSCustomObject]@{
                        ModuleName = $_.ModuleName
                        FileName = $_.FileName
                        BaseAddress = "0x" + $_.BaseAddress.ToString("X")
                        ModuleMemorySize = $_.ModuleMemorySize
                    }
                }
                $modules | ConvertTo-Json -Compress
            } catch {
                Write-Output "ERROR: " + $_.Exception.Message
            }
        `;

        const encodedScript = Buffer.from(powershellScript, "utf16le").toString("base64");
        const executionResult = await executeCommandAsync(`powershell.exe -NoProfile -NonInteractive -EncodedCommand ${encodedScript}`, { maxBuffer: 15 * 1024 * 1024 });

        const rawOutput = executionResult.stdout.trim();
        if (rawOutput.startsWith("ERROR:")) {
            return {
                isSuccessful: false,
                errorMessage: rawOutput,
                modules: [],
                process: targetProcess
            };
        }

        let moduleRawList = [];
        if (rawOutput) {
            const rawParsed = JSON.parse(rawOutput);
            moduleRawList = Array.isArray(rawParsed) ? rawParsed : [rawParsed];
        }

        const processedModules = moduleRawList.map((moduleItem) => {
            const moduleNameLower = (moduleItem.ModuleName || "").toLowerCase();
            const modulePathLower = (moduleItem.FileName || "").toLowerCase();

            let moduleCategory = "neutral";
            let recommendationScore = 50;
            let recommendationReason = "Standard dynamic library";

            if (KNOWN_SYSTEM_MODULES.has(moduleNameLower)) {
                moduleCategory = "system_protected";
                recommendationScore = 10;
                recommendationReason = "Core Windows system DLL. Proxying is not recommended due to KnownDLLs protection or system instability risk.";
            } else if (RECOMMENDED_PROXY_MODULES.has(moduleNameLower)) {
                moduleCategory = "recommended_proxy";
                const recommendationData = RECOMMENDED_PROXY_MODULES.get(moduleNameLower);
                recommendationScore = recommendationData.score;
                recommendationReason = recommendationData.reason;
            } else if (targetExecutableDirectory && modulePathLower.startsWith(targetExecutableDirectory)) {
                moduleCategory = "application_local";
                recommendationScore = 85;
                recommendationReason = "Local application DLL residing directly in the target application directory. Highly suitable for proxying.";
            }

            return {
                moduleName: moduleItem.ModuleName,
                modulePath: moduleItem.FileName,
                baseAddress: moduleItem.BaseAddress,
                moduleMemorySizeBytes: moduleItem.ModuleMemorySize,
                category: moduleCategory,
                recommendationScore: recommendationScore,
                recommendationReason: recommendationReason,
                isRecommendedForProxy: moduleCategory === "recommended_proxy" || moduleCategory === "application_local"
            };
        });

        processedModules.sort((firstModule, secondModule) => {
            if (firstModule.recommendationScore !== secondModule.recommendationScore) {
                return secondModule.recommendationScore - firstModule.recommendationScore;
            }
            return firstModule.moduleName.localeCompare(secondModule.moduleName);
        });

        return {
            isSuccessful: true,
            process: targetProcess,
            totalModulesCount: processedModules.length,
            modules: processedModules
        };
    } catch (error) {
        return {
            isSuccessful: false,
            errorMessage: "Failed to enumerate process modules: " + error.message,
            modules: []
        };
    }
}

export async function analyzeProxyCandidatesForProcess(targetIdentifierOrName) {
    try {
        const modulesResult = await enumerateProcessModules(targetIdentifierOrName);
        if (!modulesResult.isSuccessful) {
            return {
                isSuccessful: false,
                errorMessage: modulesResult.errorMessage,
                candidates: []
            };
        }

        const candidatesWithExports = [];

        for (const moduleItem of modulesResult.modules) {
            if (moduleItem.category === "system_protected") {
                continue;
            }

            let exportAnalysisResult = null;
            if (moduleItem.modulePath && fs.existsSync(moduleItem.modulePath)) {
                exportAnalysisResult = parsePeExports(moduleItem.modulePath);
            }

            const exportCount = exportAnalysisResult && exportAnalysisResult.isSuccessful
                ? exportAnalysisResult.totalExportsCount
                : 0;

            if (exportCount > 0) {
                let adjustedScore = moduleItem.recommendationScore;
                if (exportCount < 50) {
                    adjustedScore += 5;
                } else if (exportCount > 500) {
                    adjustedScore -= 10;
                }

                candidatesWithExports.push({
                    moduleName: moduleItem.moduleName,
                    modulePath: moduleItem.modulePath,
                    category: moduleItem.category,
                    score: adjustedScore,
                    reason: moduleItem.recommendationReason,
                    architecture: exportAnalysisResult.architecture,
                    is64BitArchitecture: exportAnalysisResult.is64BitArchitecture,
                    totalExportsCount: exportCount,
                    sampleExportedFunctions: exportAnalysisResult.exportedFunctions.slice(0, 10).map((exportItem) => exportItem.name)
                });
            }
        }

        candidatesWithExports.sort((firstCandidate, secondCandidate) => secondCandidate.score - firstCandidate.score);

        const bestCandidate = candidatesWithExports.length > 0 ? candidatesWithExports[0] : null;

        return {
            isSuccessful: true,
            targetProcess: modulesResult.process,
            bestRecommendation: bestCandidate,
            totalCandidatesFound: candidatesWithExports.length,
            candidates: candidatesWithExports
        };
    } catch (error) {
        return {
            isSuccessful: false,
            errorMessage: "Failed to analyze proxy candidates: " + error.message,
            candidates: []
        };
    }
}
