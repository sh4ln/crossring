#pragma once
#include "Common.h"
#include <vector>
#include <set>
#include <fstream>
#include <unordered_set>
#include <chrono>

// ============================================================
// CROSSRING Passive Monitoring - "Observe and Alert, Don't Break"
// Tasks 9-14: Non-blocking security enhancements
// ============================================================

namespace PassiveMonitor {

// ============================================
// Task 9: Kernel-Mode Threat Detection (READ-ONLY)
// ============================================
class KernelIntegrity {
public:
    static KernelIntegrity& Instance();
    
    struct ThreatIndicators {
        bool driverSigningDisabled;
        bool secureBootDisabled;
        bool syscallHooked;
        std::vector<DWORD> hiddenPids;
        std::vector<std::wstring> unsignedDrivers;
    };
    
    // Perform full scan (call periodically, not on every event)
    ThreatIndicators Scan();
    
    // Individual checks
    bool IsDriverSigningEnforced();
    std::vector<DWORD> FindHiddenProcesses();  // Optimized PID gap analysis
    bool CheckSyscallIntegrity();
    
    // Linux-specific
    bool IsKernelLockdownEnabled();
    std::vector<std::string> FindUnsignedKernelModules();
    
private:
    KernelIntegrity() = default;
    
    // Optimized: Compare Toolhelp vs NtQuerySystemInformation (not 0-65535)
    std::set<DWORD> GetToolhelpPids();
    std::set<DWORD> GetNtQueryPids();
};

// ============================================
// Task 10: Code Injection Detection (NON-BLOCKING)
// ============================================
class InjectionDetector {
public:
    static InjectionDetector& Instance();
    
    bool Initialize();
    void Shutdown();
    
    struct InjectionEvent {
        DWORD sourcePid;
        DWORD targetPid;
        std::wstring sourceProcess;
        std::wstring targetProcess;
        std::wstring apiUsed;  // WriteProcessMemory, CreateRemoteThread, etc.
        int riskScore;
        std::chrono::system_clock::time_point timestamp;
    };
    
    using InjectionCallback = std::function<void(const InjectionEvent&)>;
    void SetCallback(InjectionCallback cb) { m_callback = cb; }
    
    // Check if process is whitelisted (debuggers, game overlays, etc.)
    bool IsWhitelisted(const std::wstring& processName);
    
    // Add to permanent whitelist (user clicked "Always Allow")
    void AddToWhitelist(const std::wstring& processName);
    
    // Background RWX memory scan
    struct RwxRegion {
        DWORD pid;
        std::wstring process;
        uintptr_t address;
        size_t size;
        bool isJit;  // True if likely JIT (whitelisted)
    };
    std::vector<RwxRegion> ScanForRwxMemory();
    
private:
    InjectionDetector() = default;
    
    void EtwMonitorThread();
    int CalculateRiskScore(const InjectionEvent& event);
    
    InjectionCallback m_callback;
    std::atomic<bool> m_running{false};
    std::unique_ptr<std::thread> m_thread;
    
    // Whitelisted processes (debuggers, overlays, accessibility)
    std::unordered_set<std::wstring> m_whitelist;
    std::mutex m_mutex;
    
    // Default whitelist
    static const std::vector<std::wstring> DEFAULT_WHITELIST;
};

// ============================================
// Task 11: Update Process Whitelisting
// ============================================
class UpdateProtection {
public:
    static UpdateProtection& Instance();
    
    // Check if process is a system update (NEVER block)
    bool IsSystemUpdate(const std::wstring& path, const std::wstring& signer);
    
    // Check if process is a known installer
    bool IsKnownInstaller(const std::wstring& path, const std::wstring& signer);
    
    // Check if currently in unattended update mode
    bool IsUnattendedUpdateActive();
    
    // Log update activity
    void LogUpdateActivity(const std::wstring& process, const std::wstring& action);
    
private:
    UpdateProtection();
    
    // Windows Update paths (permanent whitelist)
    static const std::vector<std::wstring> WINDOWS_UPDATE_PATHS;
    
    // Linux package managers
    static const std::vector<std::string> LINUX_PACKAGE_MANAGERS;
    
    // Known installer vendors
    static const std::vector<std::wstring> TRUSTED_INSTALLER_VENDORS;
    
    std::ofstream m_updateLog;
    std::mutex m_logMutex;
};

// ============================================
// Task 12: Backup & Recovery Safety Net
// ============================================
class BackupManager {
public:
    static BackupManager& Instance();
    
    // Quarantine file with full metadata
    struct QuarantineEntry {
        std::wstring originalPath;
        std::wstring sha256;
        std::wstring reason;
        int64_t timestamp;
        std::vector<uint8_t> originalAcl;  // Windows ACL backup
    };
    
    bool QuarantineFile(const std::wstring& path, const std::wstring& reason);
    bool RestoreFile(const std::wstring& sha256);
    std::vector<QuarantineEntry> GetQuarantinedFiles();
    
    // Config backup (auto-saves on every change)
    void BackupConfig();
    bool RestoreConfigFromBackup();  // Uses most recent
    bool HasValidBackup();
    
    // Factory reset
    static bool CheckFactoryResetRequest();
    void PerformFactoryReset();
    
    // Protection mode change confirmation
    bool ConfirmProtectionDowngrade();  // Returns true if user typed "CONFIRM"
    
private:
    BackupManager();
    
    std::wstring GetQuarantinePath(const std::wstring& sha256);
    void PruneOldBackups(int maxBackups = 5);
    
    static constexpr const wchar_t* QUARANTINE_DIR = L"C:\\ProgramData\\CROSSRING\\Quarantine";
    static constexpr const wchar_t* FACTORY_RESET_FILE = L"C:\\CROSSRING_FACTORY_RESET.txt";
};

// ============================================
// Task 13: Performance & Resource Limits
// ============================================
class ResourceLimiter {
public:
    static ResourceLimiter& Instance();
    
    void Initialize();
    
    // CPU Management
    enum class LoadLevel { Normal, Threat, UserScan };
    void SetLoadLevel(LoadLevel level);
    bool ShouldPauseTasks();  // True if CPU budget exceeded
    void ThrottleIfNeeded();  // Call periodically
    
    // Memory Management
    bool IsWithinMemoryBudget();
    void ClearCachesIfNeeded();
    size_t GetCurrentMemoryUsage();
    
    // Disk I/O
    void SetLowIoPriority();
    bool ShouldSkipLargeFile(size_t fileSize);  // >500MB
    bool IsDiskBusy();  // >80% utilization
    
    // Idle Detection
    bool IsSystemIdle();  // No user activity for 10 mins
    void UpdateActivityTimestamp();
    
    // Startup
    void DeferNonCriticalInit();
    
    struct Stats {
        double cpuUsage;
        size_t memoryMB;
        bool isPaused;
        std::chrono::steady_clock::time_point lastActivity;
    };
    Stats GetStats();
    
private:
    ResourceLimiter() = default;
    
    double GetProcessCpuUsage();
    
    std::atomic<LoadLevel> m_loadLevel{LoadLevel::Normal};
    std::atomic<bool> m_tasksPaused{false};
    std::chrono::steady_clock::time_point m_lastActivity;
    std::mutex m_mutex;
    
    // CPU limits by load level
    static constexpr double CPU_LIMIT_NORMAL = 5.0;
    static constexpr double CPU_LIMIT_THREAT = 15.0;
    static constexpr double CPU_LIMIT_USERSCAN = 25.0;
    static constexpr size_t MEMORY_LIMIT_MB = 150;
    static constexpr size_t MAX_FILE_SIZE = 500 * 1024 * 1024;  // 500 MB
};

// ============================================
// Task 14: Telemetry & Privacy (ZERO DATA)
// ============================================
class PrivacyGuard {
public:
    static PrivacyGuard& Instance();
    
    // Verify zero network connections
    static bool VerifyNoNetworkConnections();
    
    // Local logging only
    void Log(const std::wstring& message);
    void LogThreat(const std::wstring& threatInfo);
    
    // Log rotation (30 days, compress old)
    void RotateLogs();
    
    // Export for user
    bool ExportLogsToFile(const std::wstring& outputPath);
    
    // Optional anonymous threat hash sharing
    std::wstring GetAnonymizedThreatHashes();  // For clipboard export
    
private:
    PrivacyGuard();
    
    void CompressOldLogs();
    
    std::wstring m_logDir;
    std::ofstream m_currentLog;
    std::mutex m_logMutex;
    
    static constexpr int LOG_RETENTION_DAYS = 30;
};

// ============================================
// Aggregate Manager
// ============================================
class PassiveSecurityManager {
public:
    static PassiveSecurityManager& Instance();
    
    bool InitializeAll();
    void ShutdownAll();
    
    // Run periodic passive scans (call every 5 minutes)
    void RunPeriodicChecks();
    
    // Get overall system health
    struct SystemHealth {
        bool kernelIntegrityOk;
        bool noHiddenProcesses;
        bool performanceOk;
        int activeAlerts;
    };
    SystemHealth GetSystemHealth();
    
private:
    PassiveSecurityManager() = default;
};

} // namespace PassiveMonitor
