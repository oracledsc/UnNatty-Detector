#pragma once
#include "common.h"

struct HookPattern {
    std::vector<uint8_t> pattern;
    std::string name;
};

struct HookDetectionResult {
    bool foundHooks;  // Changed back to foundHooks for consistency
    std::string sectionName;  // Changed back to sectionName
    uint64_t offset;
    std::string hookType;
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> modifiedBytes;
};

class HookDetector {
public:
    HookDetector();
    HookDetectionResult analyzeModule(const ProcessInfo& processInfo);
    void writeHookDetails(const std::string& logFilePath, const HookDetectionResult& result, bool isHook);
private:
    std::vector<HookPattern> HOOK_PATTERNS;
    std::vector<uint8_t> readMemory(DWORD pid, ULONGLONG address, SIZE_T size);
};