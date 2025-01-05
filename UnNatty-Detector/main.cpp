#include "common.h"
#include "hookdetector.h"
#include "processchecker.h"
#include "cosa.h"
#include <thread>
#include <chrono>
#include <sstream>
#include <Psapi.h>
#include <TlHelp32.h>
#include <filesystem>
#include <unordered_map>
#include <iomanip>
#include <cctype>

wchar_t* wcscasestr(const wchar_t* haystack, const wchar_t* needle) {
    if (!*needle) return (wchar_t*)haystack;

    for (; *haystack; ++haystack) {
        if (towlower(*haystack) == towlower(*needle)) {
            const wchar_t* h = haystack;
            const wchar_t* n = needle;

            while (*h && *n && towlower(*h) == towlower(*n)) {
                ++h;
                ++n;
            }

            if (!*n) return (wchar_t*)haystack;
        }
    }
    return nullptr;
}

bool IsElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isElevated;
}

bool RunAsAdmin() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;

        if (!ShellExecuteExW(&sei)) {
            return false;
        }
        return true;
    }
    return false;
}

void enableConsoleColors() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
}

void printBanner() {
    std::cout << BLUE << R"(
=======================================================
              UnNatty-Detector v2.1.0                   
                 Created by Oracle              
=======================================================)" << RESET << std::endl;
}

size_t getDiscordVoiceNodeFileSize(DWORD pid, const std::string& moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(snapshot, &moduleEntry)) {
        do {
            std::wstring moduleNameW(moduleName.begin(), moduleName.end());
            if (wcscasestr(moduleEntry.szModule, moduleNameW.c_str()) != nullptr) {
                CloseHandle(snapshot);

                HANDLE hFile = CreateFileW(
                    moduleEntry.szExePath,
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL
                );

                if (hFile != INVALID_HANDLE_VALUE) {
                    LARGE_INTEGER fileSize;
                    if (GetFileSizeEx(hFile, &fileSize)) {
                        CloseHandle(hFile);
                        return fileSize.QuadPart;
                    }
                    CloseHandle(hFile);
                }

                return 0;
            }
        } while (Module32Next(snapshot, &moduleEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

struct VoiceNodeInfo {
    std::string type;
    DWORD pid;
    size_t size;
};

std::string formatVoiceNodeSize(size_t sizeInBytes) {
    size_t sizeInKB = sizeInBytes / 1024;
    std::ostringstream formattedSize;
    formattedSize << sizeInKB;

    std::string fullSize = std::to_string(sizeInKB);
    if (fullSize.length() > 3) {
        formattedSize << fullSize.substr(fullSize.length() - 3);
        formattedSize << " KB (" << sizeInBytes << " bytes)";
    }
    else {
        formattedSize << " KB (" << sizeInBytes << " bytes)";
    }

    return formattedSize.str();
}

std::vector<VoiceNodeInfo> getVoiceNodeInfo() {
    std::vector<VoiceNodeInfo> nodeInfo;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return nodeInfo;

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(processEntry);

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            std::wstring processName = processEntry.szExeFile;
            std::string type;

            if (processName == L"Discord.exe") type = "Discord";
            else if (processName == L"DiscordPTB.exe") type = "Discord PTB";
            else if (processName == L"DiscordCanary.exe") type = "Discord Canary";
            else continue;

            size_t fileSize = getDiscordVoiceNodeFileSize(processEntry.th32ProcessID, "discord_voice.node");
            if (fileSize > 0) {
                nodeInfo.push_back({ type, processEntry.th32ProcessID, fileSize });
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return nodeInfo;
}

int main() {
    if (!IsElevated()) {
        if (RunAsAdmin()) {
            return 0;
        }
        else {
            MessageBoxA(NULL, "This application requires administrator privileges to run.\nPlease run as administrator.", "Administrator Rights Required", MB_ICONEXCLAMATION);
            return 1;
        }
    }

    enableConsoleColors();
    SetConsoleOutputCP(CP_UTF8);

    try {
        SystemLogger logger;
        logger.logPrefetch();
        logger.logUsnJournal();
        logger.logTaskList();
        logger.logFilteredTaskList();
        logger.logZombieProcesses();
        logger.logRegistryKeys();

        printBanner();
        ProcessChecker processChecker;
        HookDetector hookDetector;

        std::cout << BLUE << "[*] Scanning for Discord processes...\n\n" << RESET;

        auto processes = processChecker.findDiscordProcesses();
        auto voiceNodes = getVoiceNodeInfo();

        if (processes.empty()) {
            std::cout << RED << "[!] No Discord installations found\n" << RESET;
            std::cout << BLUE << "\n[*] Press Enter to exit..." << RESET;
            std::cin.get();
            return 1;
        }

        std::ofstream log("logs.txt", std::ios::trunc);
        log << "=======================================================\n";
        log << "              UnNatty-Detector v2.1.0                   \n";
        log << "Created by Oracle (Credit to Cosa for external detection)\n";
        log << "=======================================================\n\n";
        log << "Scan Started: " << getCurrentTimestamp() << "\n\n";
        log << "[*] Discord Process Information\n";
        log << "-------------------------------------------------------\n\n";
        log.close();

        log.open("logs.txt", std::ios::app);
        std::unordered_map<std::string, bool> foundDiscordVersions = {
            {"Discord", false},
            {"Discord PTB", false},
            {"Discord Canary", false}
        };

        for (const auto& process : processes) {
            for (const auto& node : voiceNodes) {
                if (!foundDiscordVersions[node.type] && node.type == process.version) {
                    std::cout << GREEN << "[+] Found " << node.type << " (PID: " << process.pid << ")\n" << RESET;
                    std::cout << BLUE << "    Voice Node Found at: 0x" << std::hex << process.baseAddress << std::dec << "\n";
                    std::cout << "    Voice Node Size: " << formatVoiceNodeSize(node.size) << "\n\n" << RESET;

                    log << "[+] Found " << node.type << " (PID: " << process.pid << ")\n";
                    log << "    Voice Node Found at: 0x" << std::hex << process.baseAddress << std::dec << "\n";
                    log << "    Voice Node Size: " << formatVoiceNodeSize(node.size) << "\n\n";
                    foundDiscordVersions[node.type] = true;
                }
            }
        }

        for (const auto& [version, found] : foundDiscordVersions) {
            if (!found) {
                std::cout << RED << "[!] " << version << " not detected\n" << RESET;
                log << "[!] " << version << " not detected\n\n";
            }
        }
        log.close();

        std::cout << BLUE << "\n[*] Running analysis...\n" << RESET;
        std::cout << "================================================================================\n\n";

        log.open("logs.txt", std::ios::app);
        log << "[*] Hook Analysis Results\n";
        log << "-------------------------------------------------------\n\n";

        std::vector<std::string> versions = { "Discord", "Discord Canary", "Discord PTB" };
        bool hooksFound = false;
        bool anyImGuiFound = false;
        bool anyOpusFound = false;

        for (const auto& version : versions) {
            for (const auto& process : processes) {
                if (process.version == version) {
                    std::cout << GREEN << "[+] Analyzing " << process.version << "...\n\n" << RESET;
                    log << "[+] Analyzing " << process.version << "...\n\n";

                    auto result = hookDetector.analyzeModule(process);
                    if (result.foundHooks) hooksFound = true;

                    if (hookDetector.checkForImGui()) {
                        std::cout << RED << "[!] ImGui detected in " << process.version << "\n" << RESET;
                        log << "[!] ImGui detected in " << process.version << "\n";
                        anyImGuiFound = true;
                    }

                    if (hookDetector.checkForOpusHooks()) {
                        std::cout << RED << "[!] Opus Hooks detected in " << process.version << "\n" << RESET;
                        log << "[!] Opus Hooks detected in " << process.version << "\n";
                        anyOpusFound = true;
                    }

                    auto audioResult = hookDetector.detectOtherHooks(process.pid);
                    auto hooks = hookDetector.detectAllHooks(process.pid);

                    if (!hooks.empty()) {
                        std::cout << RED << "[!] ReadOnly hooks detected in " << process.version << "\n" << RESET;
                        log << "[!] ReadOnly hooks detected in " << process.version << "\n";
                        for (const auto& hook : hooks) {
                            log << "    Hook at: 0x" << std::hex << hook.moduleBase << " in " << hook.modulePath << "\n";
                        }
                    }

                    if (!hookDetector.validateVoiceNodeIntegrity(process.path, process.pid)) {
                        std::cout << RED << "[!] Voice node integrity check failed for " << process.version << "\n" << RESET;
                        log << "[!] Voice node integrity check failed for " << process.version << "\n";
                    }

                    if (hookDetector.detectVTableHooks(process)) {
                        std::cout << RED << "[!] VTable hooks detected in " << process.version << "\n" << RESET;
                        log << "[!] VTable hooks detected in " << process.version << "\n";
                    }

                    if (hookDetector.detectPageGuardHooks()) {
                        std::cout << RED << "[!] PAGE_GUARD hooks detected in " << process.version << "\n" << RESET;
                        log << "[!] PAGE_GUARD hooks detected in " << process.version << "\n";
                    }

                    break;
                }
            }
        }

        if (!hooksFound && !anyImGuiFound && !anyOpusFound) {
            std::cout << GREEN << "[+] No hooks detected in Discord\n" << RESET;
            log << "[+] No hooks detected in Discord\n\n";
        }

        std::cout << "\033[37m\n================================================================================\n\033[0m";

        log << "\n=======================================================\n";
        log << "                  Process History                       \n";
        log << "=======================================================\n\n";
        log.close();

        processChecker.logProcessHistory();

        log.open("logs.txt", std::ios::app);
        log << "\nScan Completed: " << getCurrentTimestamp() << "\n";
        log << "=======================================================\n\n";
        log.close();

        logger.createZipFile();

        if (std::filesystem::exists("logs.txt")) {
            std::filesystem::remove("logs.txt");
        }

        std::cout << BLUE << "\n[*] All results have been saved to output.zip\n";
        std::cout << "[*] Press Enter to exit..." << RESET;
        std::cin.get();
        return 0;
    }
    catch (const std::exception& e) {
        std::cout << RED << "\n[!] Error: " << e.what() << "\n[!] Run as administrator\n" << RESET;
        std::cout << BLUE << "\n[*] Press Enter to exit..." << RESET;
        std::cin.get();
        return 1;
    }
}
