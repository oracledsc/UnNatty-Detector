#include "common.h"
#include "hookdetector.h"
#include "processchecker.h"
#include <filesystem>
#include <thread>
#include <chrono>
#include <sstream>
#include <Psapi.h>
#include <TlHelp32.h>

const wchar_t* boxChars[] = {
    L"-------------------------------------------------------",
    L"                    HOOK DETECTED                       ",
    L"               NO FALSE DETECTIONS HERE                 ",
    L"-------------------------------------------------------"
};

void NegroAscendIsChinese(const std::string& message, const char* color = "", int delayMs = 100) {
    std::cout << color << message << RESET << std::flush;
    std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
}

void HookDetector::writeHookDetails(const std::string& logFilePath, const HookDetectionResult& result, bool isHook) {
    std::ofstream outFile(logFilePath, std::ios::app);
    if (!outFile.is_open()) {
        std::cerr << "Failed to open logs.txt for writing hook details." << std::endl;
        return;
    }

    // Write detection details
    outFile << "\n" << std::string(80, '=') << "\n";
    outFile << (isHook ? "                    HOOK DETECTION ALERT\n" : "                    MEMORY PATCH DETECTED\n");
    outFile << std::string(80, '=') << "\n\n";

    outFile << "Details:\n";
    outFile << "-------------\n";
    outFile << "Section Name: " << result.sectionName << "\n";
    outFile << "Offset: 0x" << std::hex << result.offset << std::dec << "\n";
    outFile << (isHook ? "Hook Type: " : "Patch Type: ") << result.hookType << "\n";
    outFile << "Original Bytes: " << bytesToHexString(result.originalBytes) << "\n";
    outFile << "Modified Bytes: " << bytesToHexString(result.modifiedBytes) << "\n\n";

    outFile << "Integrity Status: " << (isHook ? "VIOLATED" : "PATCHED") << "\n";
    outFile << "Hook Confidence: 100% POSITIVE\n";
    outFile << std::string(80, '=') << "\n\n";
}

HookDetector::HookDetector() {
    SetConsoleOutputCP(CP_UTF8);

    HOOK_PATTERNS = {
        {{0xFF, 0x25}, "JMP FAR"},
        {{0xFF, 0x15}, "CALL FAR"},
        {{0xE9}, "JMP NEAR"},
        {{0xE8}, "CALL NEAR"},
        {{0xFF, 0x35}, "PUSH"},
        {{0x68}, "PUSH IMM"},
        {{0xFF, 0x24}, "JMP INDIRECT"},
        {{0xFF, 0x14}, "CALL INDIRECT"},
        {{0x90}, "NOP"},
        {{0xCC}, "INT3"},
        {{0xCD, 0x03}, "INT 3"},
        {{0xF3, 0x90}, "PAUSE"},
        {{0xFF, 0xFF}, "Invalid Opcode"}
    };
}

std::vector<uint8_t> HookDetector::readMemory(DWORD pid, ULONGLONG address, SIZE_T size) {
    std::vector<uint8_t> buffer(size);
    HANDLE processHandle = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (processHandle == NULL) return buffer;

    SIZE_T bytesRead;
    if (!ReadProcessMemory(processHandle, (LPCVOID)address, buffer.data(), size, &bytesRead)) {
        buffer.clear();
    }

    CloseHandle(processHandle);
    return buffer;
}

HookDetectionResult HookDetector::analyzeModule(const ProcessInfo& processInfo) {
    HookDetectionResult result;
    result.foundHooks = false;
    bool hookDetectedPrinted = false;

    HANDLE fileHandle = CreateFileA(processInfo.path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) return result;

    HANDLE processHandle = OpenProcess(PROCESS_VM_READ, FALSE, processInfo.pid);
    if (processHandle == NULL) {
        CloseHandle(fileHandle);
        return result;
    }

    DWORD fileSize = GetFileSize(fileHandle, NULL);
    std::vector<uint8_t> fileData(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(fileHandle, fileData.data(), fileSize, &bytesRead, NULL)) {
        CloseHandle(fileHandle);
        CloseHandle(processHandle);
        return result;
    }
    CloseHandle(fileHandle);

    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;

    ReadProcessMemory(processHandle, (LPCVOID)processInfo.baseAddress, &dosHeader, sizeof(dosHeader), NULL);
    ReadProcessMemory(processHandle, (LPCVOID)(processInfo.baseAddress + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), NULL);

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader;
        ReadProcessMemory(processHandle,
            (LPCVOID)(processInfo.baseAddress + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER))),
            &sectionHeader, sizeof(sectionHeader), NULL);

        if (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            std::vector<uint8_t> memoryData(sectionHeader.Misc.VirtualSize);
            ReadProcessMemory(processHandle,
                (LPCVOID)(processInfo.baseAddress + sectionHeader.VirtualAddress),
                memoryData.data(), sectionHeader.Misc.VirtualSize, NULL);

            for (size_t offset = 0; offset < memoryData.size() - 10; offset++) {
                bool foundHook = false;
                for (const auto& pattern : HOOK_PATTERNS) {
                    if (offset + pattern.pattern.size() <= memoryData.size()) {
                        if (std::equal(pattern.pattern.begin(), pattern.pattern.end(), memoryData.begin() + offset)) {
                            size_t fileOffset = sectionHeader.PointerToRawData + offset;
                            if (fileOffset + pattern.pattern.size() <= fileData.size() &&
                                !std::equal(pattern.pattern.begin(), pattern.pattern.end(),
                                    fileData.begin() + fileOffset)) {
                                result.foundHooks = true;
                                result.sectionName = std::string((char*)sectionHeader.Name, 8);
                                result.offset = sectionHeader.VirtualAddress + offset;
                                result.hookType = pattern.name;

                                if (fileOffset + pattern.pattern.size() <= fileData.size()) {
                                    result.originalBytes.assign(
                                        fileData.begin() + fileOffset,
                                        fileData.begin() + fileOffset + pattern.pattern.size()
                                    );
                                }
                                if (offset + pattern.pattern.size() <= memoryData.size()) {
                                    result.modifiedBytes.assign(
                                        memoryData.begin() + offset,
                                        memoryData.begin() + offset + pattern.pattern.size()
                                    );
                                }

                                writeHookDetails("logs.txt", result, true);

                                if (!hookDetectedPrinted) {
                                    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
                                    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                                    for (const auto& line : boxChars) {
                                        std::wcout << line << std::endl;
                                    }
                                    hookDetectedPrinted = true;
                                }
                                foundHook = true;
                                break;
                            }
                        }
                    }
                }

                if (!foundHook) {
                    size_t fileOffset = sectionHeader.PointerToRawData + offset;
                    if (fileOffset + 10 <= fileData.size()) {
                        if (!std::equal(fileData.begin() + fileOffset, fileData.begin() + fileOffset + 10, memoryData.begin() + offset)) {
                            result.sectionName = std::string((char*)sectionHeader.Name, 8);
                            result.offset = sectionHeader.VirtualAddress + offset;
                            result.hookType = "Memory Patch";

                            result.originalBytes.assign(fileData.begin() + fileOffset, fileData.begin() + fileOffset + 10);
                            result.modifiedBytes.assign(memoryData.begin() + offset, memoryData.begin() + offset + 10);

                            writeHookDetails("logs.txt", result, false);
                        }
                    }
                }
            }
        }
    }

    CloseHandle(processHandle);

    if (!result.foundHooks) {
        std::wcout << GREEN << L"[+] No hooks detected in " << processInfo.version.c_str()
            << L" \n\n" << RESET;
        std::cout << std::string(80, '=') << std::endl;
    }

    return result;
}
