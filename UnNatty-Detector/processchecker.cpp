#include "processchecker.h"
#include "common.h"
#include "xorstr.hpp"

void ProcessChecker::logProcessHistory() {
    const auto logFile = std::string(xorstr_("logs.txt"));
    std::ofstream log(logFile, std::ios::app);

    const auto header = std::string(xorstr_(R"(
---------------------- Process History ----------------------
)"));
    log << header;

    auto processes = getCurrentProcesses();
    auto historicalProcesses = getUserAssistKeys();
    processes.insert(processes.end(), historicalProcesses.begin(), historicalProcesses.end());

    std::sort(processes.begin(), processes.end(),
        [](const ProcessHistory& a, const ProcessHistory& b) {
            return CompareFileTime(&b.timestamp, &a.timestamp) < 0;
        });

    std::set<std::string> uniquePaths;
    for (const auto& process : processes) {
        if (uniquePaths.insert(process.path).second) {
            log << fileTimeToString(process.timestamp) << "  " << process.path << "\n";
        }
    }

    const auto footer = std::string(xorstr_("-------------------------------------------------------\n\n"));
    log << footer;
}

std::vector<ProcessInfo> ProcessChecker::findDiscordProcesses() {
    std::vector<ProcessInfo> foundProcesses;

    const auto discord_exe = std::string(xorstr_("discord.exe"));
    const auto discord_name = std::string(xorstr_("Discord"));
    const auto discordcanary_exe = std::string(xorstr_("discordcanary.exe"));
    const auto discord_canary_name = std::string(xorstr_("Discord Canary"));
    const auto discordptb_exe = std::string(xorstr_("discordptb.exe"));
    const auto discord_ptb_name = std::string(xorstr_("Discord PTB"));

    std::map<std::string, std::string> discordVersions = {
        {discord_exe, discord_name},
        {discordcanary_exe, discord_canary_name},
        {discordptb_exe, discord_ptb_name}
    };

    const auto logFile = std::string(xorstr_("logs.txt"));
    std::ofstream log(logFile, std::ios::app);

    const auto header = std::string(xorstr_(R"(
-------------------- Discord Analysis ----------------------
)"));
    log << header;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return foundProcesses;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    std::set<std::string> foundVersions;

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            std::wstring wProcessName = pe32.szExeFile;
            std::string processName(wProcessName.begin(), wProcessName.end());
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            auto it = discordVersions.find(processName);
            if (it != discordVersions.end()) {
                foundVersions.insert(processName);
                const auto found_msg = std::string(xorstr_("[+] Found "));
                const auto pid_msg = std::string(xorstr_(" (PID: "));
                log << found_msg << it->second << pid_msg << pe32.th32ProcessID << ")\n";

                HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (processHandle) {
                    HMODULE modules[1024];
                    DWORD needed;
                    if (EnumProcessModules(processHandle, modules, sizeof(modules), &needed)) {
                        for (unsigned i = 0; i < (needed / sizeof(HMODULE)); i++) {
                            char modPath[MAX_PATH];
                            if (GetModuleFileNameExA(processHandle, modules[i], modPath, sizeof(modPath))) {
                                std::string modulePath = modPath;
                                const auto voice_node = std::string(xorstr_("discord_voice.node"));

                                if (modulePath.find(voice_node) != std::string::npos) {
                                    ProcessInfo info;
                                    info.pid = pe32.th32ProcessID;
                                    info.baseAddress = (ULONGLONG)modules[i];
                                    info.path = modulePath;
                                    info.version = it->second;
                                    foundProcesses.push_back(info);

                                    WIN32_FILE_ATTRIBUTE_DATA fileAttr;
                                    if (GetFileAttributesExA(modulePath.c_str(), GetFileExInfoStandard, &fileAttr)) {
                                        LARGE_INTEGER fileSize;
                                        fileSize.LowPart = fileAttr.nFileSizeLow;
                                        fileSize.HighPart = fileAttr.nFileSizeHigh;

                                        const auto size_msg = std::string(xorstr_("    Voice Node Size: "));
                                        const auto bytes_msg = std::string(xorstr_(" bytes\n"));
                                        const auto addr_msg = std::string(xorstr_("    Base Address: 0x"));

                                        log << size_msg << fileSize.QuadPart << bytes_msg;
                                        log << addr_msg << std::hex << info.baseAddress << std::dec << "\n";
                                    }
                                }
                            }
                        }
                    }
                    CloseHandle(processHandle);
                }
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);

    for (const auto& version : discordVersions) {
        if (foundVersions.find(version.first) == foundVersions.end()) {
            const auto not_detected_prefix = std::string(xorstr_("[!] "));
            const auto not_detected_suffix = std::string(xorstr_(" not detected\n"));
            log << not_detected_prefix << version.second << not_detected_suffix;
        }
    }

    const auto footer = std::string(xorstr_("-------------------------------------------------------\n\n"));
    log << footer;
    return foundProcesses;
}

std::vector<ProcessHistory> ProcessChecker::getCurrentProcesses() {
    std::vector<ProcessHistory> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(snapshot, &pe32)) {
            do {
                HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (processHandle) {
                    char path[MAX_PATH];
                    if (GetModuleFileNameExA(processHandle, NULL, path, MAX_PATH)) {
                        FILETIME creation, exit, kernel, user;
                        if (GetProcessTimes(processHandle, &creation, &exit, &kernel, &user)) {
                            ProcessHistory entry;
                            entry.path = path;
                            entry.timestamp = creation;
                            processes.push_back(entry);
                        }
                    }
                    CloseHandle(processHandle);
                }
            } while (Process32NextW(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }
    return processes;
}

std::vector<ProcessHistory> ProcessChecker::getUserAssistKeys() {
    std::vector<ProcessHistory> history;
    HKEY hKey;
    const auto regPath = std::string(xorstr_("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"));

    if (RegOpenKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char guidName[MAX_PATH];
        DWORD guidIndex = 0, guidNameSize = MAX_PATH;

        while (RegEnumKeyExA(hKey, guidIndex++, guidName, &guidNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSubKey;
            const auto countKey = std::string(xorstr_("\\Count"));
            std::string subKeyPath = regPath + "\\" + guidName + countKey;

            if (RegOpenKeyExA(HKEY_CURRENT_USER, subKeyPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                char valueName[MAX_PATH];
                DWORD valueNameSize = MAX_PATH;
                DWORD valueIndex = 0;

                while (RegEnumValueA(hSubKey, valueIndex++, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    std::string decodedName = decodeRot13(valueName);
                    std::transform(decodedName.begin(), decodedName.end(), decodedName.begin(), ::tolower);

                    const auto exeExt = std::string(xorstr_(".exe"));
                    if (decodedName.find(exeExt) != std::string::npos) {
                        BYTE data[1024];
                        DWORD dataSize = sizeof(data);
                        if (RegQueryValueExA(hSubKey, valueName, NULL, NULL, data, &dataSize) == ERROR_SUCCESS) {
                            if (dataSize >= 68) {
                                ProcessHistory entry;
                                entry.path = decodedName;
                                memcpy(&entry.timestamp, data + 60, sizeof(FILETIME));
                                history.push_back(entry);
                            }
                        }
                    }
                    valueNameSize = MAX_PATH;
                }
                RegCloseKey(hSubKey);
            }
            guidNameSize = MAX_PATH;
        }
        RegCloseKey(hKey);
    }
    return history;
}

std::string ProcessChecker::decodeRot13(const std::string& input) {
    std::string result = input;
    for (char& c : result) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            c = (c - base + 13) % 26 + base;
        }
    }
    return result;
}