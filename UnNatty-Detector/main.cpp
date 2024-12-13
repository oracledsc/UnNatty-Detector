#include "common.h"
#include "hookdetector.h"
#include "processchecker.h"
#include <filesystem>
#include <thread>
#include <chrono>
#include <sstream>
#include <Psapi.h>
#include <TlHelp32.h>
#include "xorstr.hpp"
#define WHITE "\033[37m"
// VM_START

namespace fs = std::filesystem;

void printBanner() {
    const char* banner = xorstr_(R"(
=======================================================
              UnNatty-Detector v1.4                   
                Created by Oracle                       
=======================================================)");
    std::cout << BLUE << banner << RESET << std::endl;
}

void logConsoleOnly(const std::string& message, const char* color = "", int delayMs = 100) {
    std::cout << color << message << RESET << std::flush;
    std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
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

std::vector<std::tuple<std::string, DWORD, size_t>> getVoiceNodeInfo() {
    std::vector<std::tuple<std::string, DWORD, size_t>> nodeInfo;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return nodeInfo;

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(processEntry);

    const wchar_t* discord_exe = xorstr_(L"Discord.exe");
    const wchar_t* discord_ptb = xorstr_(L"DiscordPTB.exe");
    const wchar_t* discord_canary = xorstr_(L"DiscordCanary.exe");
    const char* discord_node = xorstr_("discord_voice.node");

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            std::wstring processName = processEntry.szExeFile;
            std::string type;

            if (wcscmp(processName.c_str(), discord_exe) == 0) type = "Discord";
            else if (wcscmp(processName.c_str(), discord_ptb) == 0) type = "Discord PTB";
            else if (wcscmp(processName.c_str(), discord_canary) == 0) type = "Discord Canary";
            else continue;

            size_t moduleSize = getModuleMemorySize(processEntry.th32ProcessID, discord_node);
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
    std::ofstream log("logs.txt");

    try {
        printBanner();
        ProcessChecker processChecker;
        HookDetector hookDetector;

        auto processes = processChecker.findDiscordProcesses();
        if (processes.empty()) {
            const char* noDiscordMsg = xorstr_("\n[!] No Discord installations found\n");
            logConsoleOnly(noDiscordMsg, RED);
            return 1;
        }

        const char* header1 = xorstr_("=======================================================\n");
        const char* header2 = xorstr_("                Discord Information                     \n");
        log << header1;
        log << header2;
        log << header1 << "\n";

        const char* analyzingMsg = xorstr_("\n[*] Analyzing discord_voice.node...\n");
        logConsoleOnly(analyzingMsg, BLUE);
        auto voiceNodes = getVoiceNodeInfo();

        const char* version_str = xorstr_("Discord Version: ");
        const char* pid_str = xorstr_("Process ID: ");
        const char* addr_str = xorstr_("Base Address: 0x");
        const char* size_str = xorstr_("Voice Node Size: ");
        const char* bytes_str = xorstr_(" bytes\n");
        const char* separator = xorstr_("-------------------------------------------------------\n\n");

        for (const auto& process : processes) {
            log << version_str << process.version << "\n";
            log << pid_str << process.pid << "\n";
            log << addr_str << std::hex << process.baseAddress << std::dec << "\n";

            for (const auto& [type, pid, size] : voiceNodes) {
                if (type == process.version) {
                    log << size_str << size << bytes_str;
                    break;
                }
            }
            log << separator;

            std::string foundMsg = "[+] Found " + process.version + "\n";
            logConsoleOnly(foundMsg, GREEN);
        }

        const char* historyMsg = xorstr_("\n[*] Logging process history...\n");
        logConsoleOnly(historyMsg, BLUE);
        processChecker.logProcessHistory();

        const char* hookHeader = xorstr_("                    Hook Analysis                       \n");
        log << header1;
        log << hookHeader;
        log << header1 << "\n";

        const char* analyzingHooksMsg = xorstr_("\n[*] Analyzing for hooks...\n\n");
        const char* separator2 = xorstr_("================================================================================\n");

        logConsoleOnly(analyzingHooksMsg, BLUE);
        logConsoleOnly(separator2);

        for (const auto& process : processes) {
            std::string analyzeMsg = "\n[+] Analyzing " + process.version + "...\n\n";
            logConsoleOnly(analyzeMsg, GREEN);
            auto result = hookDetector.analyzeModule(process);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        logConsoleOnly(separator2, WHITE);

        const char* savedMsg = xorstr_("\n[*] Results saved to logs.txt\n");
        const char* exitMsg = xorstr_("[*] Press Enter to exit...");
        logConsoleOnly(savedMsg, BLUE);
        logConsoleOnly(exitMsg, BLUE);
        std::cin.get();
        return 0;

    }
    catch (const std::exception& e) {
        std::string errorMsg = "\n[!] Error: ";
        errorMsg += e.what();
        errorMsg += "\n[!] Run as administrator\n";
        logConsoleOnly(errorMsg, RED);
        return 1;
    }
}
// VM_END