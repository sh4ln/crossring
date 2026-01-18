#pragma once
#include "Common.h"
#include <unordered_set>
#include <unordered_map>
#include <algorithm>

// Zero Trust Security Model for CROSSRING
// Principle: "Never trust, always verify"

class ZeroTrustEngine {
public:
    static ZeroTrustEngine& Instance();
    
    bool Initialize();
    
    // Trust levels
    enum class TrustLevel {
        Untrusted = 0,      // Unknown, block by default
        LowTrust = 1,       // First seen, suspicious indicators
        MediumTrust = 2,    // Seen before, no bad behavior
        HighTrust = 3,      // Signed by trusted publisher
        SystemTrust = 4     // Windows system component
    };
    
    // Evaluate trust for a process
    struct TrustEvaluation {
        TrustLevel level;
        int riskScore;          // 0-100
        std::vector<std::wstring> riskFactors;
        std::vector<std::wstring> trustFactors;
        bool requiresAuth;
    };
    
    TrustEvaluation EvaluateProcess(const ProcessEvent& event);
    TrustEvaluation EvaluateScript(const std::wstring& content, const std::wstring& source);
    TrustEvaluation EvaluateNetwork(const NetworkEvent& event);
    
    // Behavioral analysis
    void RecordBehavior(DWORD pid, const std::wstring& action);
    bool HasSuspiciousBehavior(DWORD pid);
    
    // Continuous verification
    bool VerifyContinuously(DWORD pid);  // Re-check running processes
    
private:
    ZeroTrustEngine() = default;
    
    // Risk scoring
    int CalculateProcessRisk(const ProcessEvent& event);
    int CalculateNetworkRisk(const NetworkEvent& event);
    
    // Known bad indicators
    bool HasKnownBadHash(const std::wstring& hash);
    bool HasSuspiciousPath(const std::wstring& path);
    bool HasSuspiciousCommandLine(const std::wstring& cmdLine);
    bool IsFromUntrustedLocation(const std::wstring& path);
    
    // Behavioral tracking
    struct ProcessBehavior {
        DWORD pid;
        std::vector<std::wstring> actions;
        std::chrono::steady_clock::time_point lastSeen;
        int suspiciousActionCount;
    };
    std::unordered_map<DWORD, ProcessBehavior> m_behaviors;
    std::mutex m_behaviorMutex;
    
    // Known malicious hashes (offline database)
    std::unordered_set<std::wstring> m_knownBadHashes;
    
    // Suspicious paths
    std::vector<std::wstring> m_suspiciousPaths;
    
    // Suspicious command line patterns
    std::vector<std::wstring> m_suspiciousCmdPatterns;
};

// Risk factors for Zero Trust evaluation
namespace RiskFactors {
    constexpr int UNSIGNED_EXECUTABLE = 20;
    constexpr int FIRST_SEEN = 15;
    constexpr int TEMP_FOLDER = 25;
    constexpr int DOWNLOADS_FOLDER = 10;
    constexpr int USB_DRIVE = 30;
    constexpr int OBFUSCATED_SCRIPT = 35;
    constexpr int KNOWN_BAD_HASH = 100;
    constexpr int LOLBIN_ABUSE = 40;
    constexpr int NETWORK_TO_INTERNET = 15;
    constexpr int SUSPICIOUS_PORT = 25;
    constexpr int CHILD_OF_BROWSER = 20;
    constexpr int CHILD_OF_OFFICE = 30;
    constexpr int MEMORY_INJECTION = 50;
}

// Trust factors (reduce risk)
namespace TrustFactors {
    constexpr int MICROSOFT_SIGNED = -40;
    constexpr int KNOWN_PUBLISHER = -30;
    constexpr int WHITELISTED = -100;
    constexpr int SYSTEM_PATH = -25;
    constexpr int SEEN_MANY_TIMES = -15;
    constexpr int LONG_RUNTIME_NO_ISSUES = -20;
}
