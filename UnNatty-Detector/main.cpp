
#include "common.h"
#include "hookdetector.h"
#include "processchecker.h"
#include <thread>
#include <chrono>
#include <sstream>
#include <Psapi.h>
#include <TlHelp32.h>
#include <filesystem>
#include <unordered_map>

void printBanner() {
    std::cout << BLUE << R"(
=======================================================
              UnNatty-Detector v2.0.0                   
                Created by Oracle                       
=======================================================)" << RESET << std::endl;
}

size_t getModuleMemorySize(DWORD pid, const std::string& moduleName) {
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (processHandle == NULL) return 0;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    size_t moduleSize = 0;

    if (EnumProcessModules(processHandle, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char modName[MAX_PATH];
            if (GetModuleFileNameExA(processHandle, hMods[i], modName, sizeof(modName))) {
                if (std::string(modName).find(moduleName) != std::string::npos) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(processHandle, hMods[i], &modInfo, sizeof(MODULEINFO))) {
                        moduleSize = modInfo.SizeOfImage;
                        break;
                    }
                }
            }
        }
    }

    CloseHandle(processHandle);
    return moduleSize;
}

struct VoiceNodeInfo {
    std::string type;
    DWORD pid;
    size_t size;
};

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

            size_t moduleSize = getModuleMemorySize(processEntry.th32ProcessID, "discord_voice.node");
            if (moduleSize > 0) {
                nodeInfo.push_back({ type, processEntry.th32ProcessID, moduleSize });
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return nodeInfo;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    std::ofstream log("logs.txt", std::ios::trunc);
    log.close();

    try {
        printBanner();
        std::cout << "\n";
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

        std::ofstream log("logs.txt", std::ios::app);
        log << "=======================================================\n";
        log << "              UnNatty-Detector v2.0.0                   \n";
        log << "                Created by Oracle                       \n";
        log << "=======================================================\n\n";
        log << "Scan Started: " << getCurrentTimestamp() << "\n\n";

        log << "[*] Discord Process Information\n";
        log << "-------------------------------------------------------\n\n";

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
                    std::cout << "    Voice Node Size: " << node.size << " bytes\n\n" << RESET;

                    log << "[+] Found " << node.type << " (PID: " << process.pid << ")\n";
                    log << "    Voice Node Found at: 0x" << std::hex << process.baseAddress << std::dec << "\n";
                    log << "    Voice Node Size: " << node.size << " bytes\n\n";
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

        std::cout << BLUE << "\n[*] Running comprehensive analysis...\n" << RESET;
        std::cout << "================================================================================\n\n";

        log << "[*] Hook Analysis Results\n";
        log << "-------------------------------------------------------\n\n";

        bool hooksFound = false;
        bool anyImGuiFound = false;
        bool anyOpusFound = false;
        for (const auto& process : processes) {
            for (const auto& node : voiceNodes) {
                if (node.type == process.version) {
                    std::cout << GREEN << "[+] Analyzing " << process.version << "...\n\n" << RESET;
                    log << "[+] Analyzing " << process.version << "...\n\n";

                    auto result = hookDetector.analyzeModule(process);
                    if (result.foundHooks) {
                        hooksFound = true;
                    
                    }
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
                }
            }
        }

        if (!hooksFound &&  !anyImGuiFound && !anyOpusFound) {
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

        std::cout << BLUE << "\n[*] All results have been saved to logs.txt\n" << RESET;
        std::cout << BLUE << "[*] Press Enter to exit..." << RESET;
        std::cin.get();
        return 0;
    }
    catch (const std::exception& e) {
        std::cout << RED << "\n[!] Error: " << e.what() << "\n[!] Run as administrator\n" << RESET;

        std::ofstream log("logs.txt", std::ios::app);
        log << "\n[!] Error: " << e.what() << "\n[!] Run as administrator\n";

        std::cout << BLUE << "\n[*] Press Enter to exit..." << RESET;
        std::cin.get();
        return 1;
    }
}
