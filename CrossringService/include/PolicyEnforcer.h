#pragma once
#include "Common.h"
#include <unordered_set>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

class PolicyEnforcer {
public:
    static PolicyEnforcer& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // Check if execution should be allowed
    enum class ExecutionResult {
        Allowed,        // Whitelisted or system process
        Blocked,        // Unknown, needs authorization
        Denied          // Explicitly denied
    };
    
    ExecutionResult CheckExecution(const ProcessEvent& event);
    
    // Decision handling
    void ApplyDecision(uint64_t eventId, Decision decision, const ProcessEvent& event);
    
    // LOLBin detection
    bool IsLolBin(const std::wstring& imagePath);
    bool IsLolBinAbuse(const std::wstring& imagePath, const std::wstring& commandLine);
    
    // System process detection
    bool IsSystemProcess(const std::wstring& imagePath);
    bool IsMicrosoftSigned(const std::wstring& imagePath);
    
private:
    PolicyEnforcer() = default;
    ~PolicyEnforcer() = default;
    PolicyEnforcer(const PolicyEnforcer&) = delete;
    PolicyEnforcer& operator=(const PolicyEnforcer&) = delete;
    
    void LoadLolBinPatterns();
    
    // LOLBin executable names (lowercase)
    std::vector<std::wstring> m_lolBins;
    
    // Suspicious command-line patterns for LOLBins
    struct LolBinPattern {
        std::wstring executable;
        std::vector<std::wstring> suspiciousArgs;
    };
    std::vector<LolBinPattern> m_lolBinPatterns;
    
    // Session-based allowances (cleared on service restart)
    std::unordered_set<std::wstring> m_sessionAllowed;
    std::mutex m_sessionMutex;
};
