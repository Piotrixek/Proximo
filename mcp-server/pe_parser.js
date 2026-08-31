import fs from "fs";
import path from "path";

export function parsePeExports(targetFilePath) {
    try {
        if (!fs.existsSync(targetFilePath)) {
            return {
                isSuccessful: false,
                errorMessage: "Target file does not exist: " + targetFilePath,
                exportedFunctions: [],
                architecture: "unknown"
            };
        }

        const fileBuffer = fs.readFileSync(targetFilePath);
        if (fileBuffer.length < 64) {
            return {
                isSuccessful: false,
                errorMessage: "File is too small to be a valid PE file",
                exportedFunctions: [],
                architecture: "unknown"
            };
        }

        const dosMagicNumber = fileBuffer.readUInt16LE(0);
        if (dosMagicNumber !== 0x5a4d) {
            return {
                isSuccessful: false,
                errorMessage: "Invalid DOS header signature (not MZ)",
                exportedFunctions: [],
                architecture: "unknown"
            };
        }

        const peHeaderOffset = fileBuffer.readUInt32LE(0x3c);
        if (peHeaderOffset + 24 > fileBuffer.length) {
            return {
                isSuccessful: false,
                errorMessage: "PE header offset is out of file bounds",
                exportedFunctions: [],
                architecture: "unknown"
            };
        }

        const peSignature = fileBuffer.readUInt32LE(peHeaderOffset);
        if (peSignature !== 0x00004550) {
            return {
                isSuccessful: false,
                errorMessage: "Invalid PE signature (not PE\\0\\0)",
                exportedFunctions: [],
                architecture: "unknown"
            };
        }

        const machineType = fileBuffer.readUInt16LE(peHeaderOffset + 4);
        const numberOfSections = fileBuffer.readUInt16LE(peHeaderOffset + 6);
        const sizeOfOptionalHeader = fileBuffer.readUInt16LE(peHeaderOffset + 20);

        const optionalHeaderOffset = peHeaderOffset + 24;
        const optionalHeaderMagic = fileBuffer.readUInt16LE(optionalHeaderOffset);

        let is64BitArchitecture = false;
        let architectureName = "x86";

        if (optionalHeaderMagic === 0x020b || machineType === 0x8664) {
            is64BitArchitecture = true;
            architectureName = "x64";
        } else if (optionalHeaderMagic === 0x010b || machineType === 0x014c) {
            is64BitArchitecture = false;
            architectureName = "x86";
        } else {
            architectureName = "unknown";
        }

        const numberOfRvaAndSizesOffset = is64BitArchitecture
            ? optionalHeaderOffset + 108
            : optionalHeaderOffset + 92;

        if (numberOfRvaAndSizesOffset + 4 > fileBuffer.length) {
            return {
                isSuccessful: false,
                errorMessage: "Optional header is truncated",
                exportedFunctions: [],
                architecture: architectureName
            };
        }

        const numberOfDataDirectories = fileBuffer.readUInt32LE(numberOfRvaAndSizesOffset);
        if (numberOfDataDirectories === 0) {
            return {
                isSuccessful: true,
                errorMessage: null,
                exportedFunctions: [],
                architecture: architectureName,
                totalExportsCount: 0
            };
        }

        const exportDirectoryEntryOffset = numberOfRvaAndSizesOffset + 4;
        const exportTableVirtualAddress = fileBuffer.readUInt32LE(exportDirectoryEntryOffset);
        const exportTableSize = fileBuffer.readUInt32LE(exportDirectoryEntryOffset + 4);

        if (exportTableVirtualAddress === 0 || exportTableSize === 0) {
            return {
                isSuccessful: true,
                errorMessage: null,
                exportedFunctions: [],
                architecture: architectureName,
                totalExportsCount: 0
            };
        }

        const sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
        const sectionHeaders = [];

        for (let sectionIndex = 0; sectionIndex < numberOfSections; sectionIndex++) {
            const currentSectionOffset = sectionHeadersOffset + (sectionIndex * 40);
            if (currentSectionOffset + 40 > fileBuffer.length) {
                break;
            }

            const virtualSize = fileBuffer.readUInt32LE(currentSectionOffset + 8);
            const virtualAddress = fileBuffer.readUInt32LE(currentSectionOffset + 12);
            const sizeOfRawData = fileBuffer.readUInt32LE(currentSectionOffset + 16);
            const pointerToRawData = fileBuffer.readUInt32LE(currentSectionOffset + 20);

            sectionHeaders.push({
                virtualSize: virtualSize,
                virtualAddress: virtualAddress,
                sizeOfRawData: sizeOfRawData,
                pointerToRawData: pointerToRawData
            });
        }

        function convertVirtualAddressToFileOffset(virtualAddress) {
            for (const section of sectionHeaders) {
                const sectionEndVirtualAddress = section.virtualAddress + Math.max(section.virtualSize, section.sizeOfRawData);
                if (virtualAddress >= section.virtualAddress && virtualAddress < sectionEndVirtualAddress) {
                    const relativeOffset = virtualAddress - section.virtualAddress;
                    return section.pointerToRawData + relativeOffset;
                }
            }
            return null;
        }

        function readNullTerminatedAsciiString(fileOffset) {
            if (fileOffset === null || fileOffset >= fileBuffer.length) {
                return "";
            }
            let currentOffset = fileOffset;
            const characterCodes = [];
            while (currentOffset < fileBuffer.length && fileBuffer[currentOffset] !== 0) {
                characterCodes.push(fileBuffer[currentOffset]);
                currentOffset++;
            }
            return Buffer.from(characterCodes).toString("ascii");
        }

        const exportDirectoryFileOffset = convertVirtualAddressToFileOffset(exportTableVirtualAddress);
        if (exportDirectoryFileOffset === null || exportDirectoryFileOffset + 40 > fileBuffer.length) {
            return {
                isSuccessful: false,
                errorMessage: "Cannot resolve export directory file offset",
                exportedFunctions: [],
                architecture: architectureName
            };
        }

        const ordinalBase = fileBuffer.readUInt32LE(exportDirectoryFileOffset + 16);
        const numberOfFunctions = fileBuffer.readUInt32LE(exportDirectoryFileOffset + 20);
        const numberOfNames = fileBuffer.readUInt32LE(exportDirectoryFileOffset + 24);
        const addressOfFunctionsRva = fileBuffer.readUInt32LE(exportDirectoryFileOffset + 28);
        const addressOfNamesRva = fileBuffer.readUInt32LE(exportDirectoryFileOffset + 32);
        const addressOfNameOrdinalsRva = fileBuffer.readUInt32LE(exportDirectoryFileOffset + 36);

        const addressOfFunctionsFileOffset = convertVirtualAddressToFileOffset(addressOfFunctionsRva);
        const addressOfNamesFileOffset = convertVirtualAddressToFileOffset(addressOfNamesRva);
        const addressOfNameOrdinalsFileOffset = convertVirtualAddressToFileOffset(addressOfNameOrdinalsRva);

        const exportedFunctions = [];
        const namedOrdinalMapping = new Map();

        if (addressOfNamesFileOffset !== null && addressOfNameOrdinalsFileOffset !== null) {
            for (let nameIndex = 0; nameIndex < numberOfNames; nameIndex++) {
                const namePointerOffset = addressOfNamesFileOffset + (nameIndex * 4);
                const ordinalPointerOffset = addressOfNameOrdinalsFileOffset + (nameIndex * 2);

                if (namePointerOffset + 4 <= fileBuffer.length && ordinalPointerOffset + 2 <= fileBuffer.length) {
                    const functionNameRva = fileBuffer.readUInt32LE(namePointerOffset);
                    const functionOrdinalIndex = fileBuffer.readUInt16LE(ordinalPointerOffset);
                    const functionNameFileOffset = convertVirtualAddressToFileOffset(functionNameRva);
                    const functionNameString = readNullTerminatedAsciiString(functionNameFileOffset);

                    namedOrdinalMapping.set(functionOrdinalIndex, functionNameString);
                }
            }
        }

        if (addressOfFunctionsFileOffset !== null) {
            for (let functionIndex = 0; functionIndex < numberOfFunctions; functionIndex++) {
                const functionAddressPointerOffset = addressOfFunctionsFileOffset + (functionIndex * 4);
                if (functionAddressPointerOffset + 4 <= fileBuffer.length) {
                    const functionAddressRva = fileBuffer.readUInt32LE(functionAddressPointerOffset);
                    if (functionAddressRva !== 0) {
                        const calculatedOrdinal = ordinalBase + functionIndex;
                        const functionNameString = namedOrdinalMapping.get(functionIndex) || ("ordinal_" + calculatedOrdinal);
                        
                        let isForwarder = false;
                        let forwarderTargetName = null;

                        if (functionAddressRva >= exportTableVirtualAddress &&
                            functionAddressRva < (exportTableVirtualAddress + exportTableSize)) {
                            isForwarder = true;
                            const forwarderFileOffset = convertVirtualAddressToFileOffset(functionAddressRva);
                            forwarderTargetName = readNullTerminatedAsciiString(forwarderFileOffset);
                        }

                        exportedFunctions.push({
                            name: functionNameString,
                            ordinal: calculatedOrdinal,
                            relativeVirtualAddress: "0x" + functionAddressRva.toString(16).toUpperCase(),
                            isForwarded: isForwarder,
                            forwarderTarget: forwarderTargetName,
                            isExportedByName: namedOrdinalMapping.has(functionIndex)
                        });
                    }
                }
            }
        }

        return {
            isSuccessful: true,
            errorMessage: null,
            filePath: targetFilePath,
            fileName: path.basename(targetFilePath),
            architecture: architectureName,
            is64BitArchitecture: is64BitArchitecture,
            totalExportsCount: exportedFunctions.length,
            exportedFunctions: exportedFunctions
        };
    } catch (unexpectedException) {
        return {
            isSuccessful: false,
            errorMessage: "Unexpected exception while parsing PE file: " + unexpectedException.message,
            exportedFunctions: [],
            architecture: "unknown"
        };
    }
}
