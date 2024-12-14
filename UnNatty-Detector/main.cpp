#include "common.h"
#include "hookdetector.h"
#include "processchecker.h"
#include <filesystem>
#include <thread>
#include <chrono>
#include <sstream>
#include <Psapi.h>
#include <TlHelp32.h>
#define WHITE "\033[37m"


namespace fs = std::filesystem;

void printBanner() {
    std::cout << BLUE << R"(
=======================================================
              UnNatty-Detector v1.4.1                   
                Created by Oracle                       
=======================================================)" << RESET << std::endl;
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
    std::ofstream log("logs.txt");

    try {

        printBanner();
        ProcessChecker processChecker;
        HookDetector hookDetector;

        auto processes = processChecker.findDiscordProcesses();
        if (processes.empty()) {
            logConsoleOnly("\n[!] No Discord installations found\n", RED);
            return 1;
        }

        log << "=======================================================\n";
        log << "                Discord Information                     \n";
        log << "=======================================================\n\n";

        logConsoleOnly("\n[*] Checking discord_voice.node...\n", BLUE);
        auto voiceNodes = getVoiceNodeInfo();

        for (const auto& process : processes) {
            log << "Discord Version: " << process.version << "\n";
            log << "Process ID: " << process.pid << "\n";
            log << "Base Address: 0x" << std::hex << process.baseAddress << std::dec << "\n";

            for (const auto& [type, pid, size] : voiceNodes) {
                if (type == process.version) {
                    log << "Voice Node Size: " << size << " bytes\n";
                    break;
                }
            }
            log << "-------------------------------------------------------\n\n";

            logConsoleOnly("[+] Found " + process.version + "\n", GREEN);
        }

        logConsoleOnly("\n[*] Logging process history...\n", BLUE);
        processChecker.logProcessHistory();

        log << "=======================================================\n";
        log << "                    Hook Analysis                       \n";
        log << "=======================================================\n\n";

        logConsoleOnly("\n[*] Analyzing for hooks...\n\n", BLUE);
        logConsoleOnly("================================================================================\n");
        for (const auto& process : processes) {
            logConsoleOnly("\n[+] Analyzing " + process.version + "...\n\n", GREEN);
            auto result = hookDetector.analyzeModule(process);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        logConsoleOnly("\n[*] Results saved to logs.txt\n", BLUE);
        logConsoleOnly("[*] Press Enter to exit...", BLUE);
        std::cin.get();
        return 0;

    }
    catch (const std::exception& e) {
        logConsoleOnly(std::string("\n[!] Error: ") + e.what() + "\n[!] Run as administrator\n", RED);
        return 1;
    }
}
