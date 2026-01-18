#pragma once
#include "Common.h"
#include <vector>
#include <unordered_set>

// ============================================================
// CROSSRING Security Core - Universal Zero Trust Implementation
// ============================================================

namespace Security {

// ============================================
// Task 1: Self-Immunity with Symlink Protection
// ============================================
class SelfProtection {
public:
    static SelfProtection& Instance();
    
    // Initialize on startup - resolve all canonical paths
    bool Initialize(const std::wstring& installDir);
    
    // Check if a path targets a protected binary (symlink-resistant)
    bool IsProtectedBinary(const std::wstring& path);
    
    // Verify integrity of protected binaries
    bool VerifyProtectedIntegrity();
    
    struct ProtectedBinary {
        std::wstring canonicalPath;
        std::wstring sha256Hash;
    };
    
    const std::vector<ProtectedBinary>& GetProtectedBinaries() const { return m_protectedBinaries; }
    
private:
    SelfProtection() = default;
    
    // Resolve canonical path (handles symlinks, junctions, hardlinks)
    std::wstring ResolveRealPath(const std::wstring& path);
    
    std::vector<ProtectedBinary> m_protectedBinaries;
    std::wstring m_installDir;
    std::mutex m_mutex;
};

// ============================================
// Task 2: Safe Mode Challenge (Visual CAPTCHA)
// ============================================
class SafeModeChallenge {
public:
    static SafeModeChallenge& Instance();
    
    // Start monitoring for safemode file
    void StartMonitoring();
    void StopMonitoring();
    
    // Generate visual CAPTCHA challenge
    struct Challenge {
        int operand1;
        int operand2;
        int correctAnswer;
        std::vector<uint8_t> captchaImage;  // PNG data
        std::chrono::steady_clock::time_point expiry;
    };
    
    Challenge GenerateChallenge();
    bool ValidateChallenge(const Challenge& challenge, int userAnswer);
    
    // Callback when safe mode is triggered
    using SafeModeCallback = std::function<void()>;
    void SetCallback(SafeModeCallback cb) { m_callback = cb; }
    
private:
    SafeModeChallenge() = default;
    
    void MonitorThread();
    std::vector<uint8_t> RenderMathCaptcha(int a, int b);
    
    std::atomic<bool> m_running{false};
    std::unique_ptr<std::thread> m_thread;
    SafeModeCallback m_callback;
    
#ifdef _WIN32
    static constexpr const wchar_t* SAFEMODE_FILE = L"C:\\CROSSRING_SAFEMODE.txt";
#else
    static constexpr const char* SAFEMODE_FILE = "/tmp/crossring_safemode";
#endif
    static constexpr int CHALLENGE_TIMEOUT_SECONDS = 30;
};

// ============================================
// Task 3: Event-Driven System Cache
// ============================================
class SystemCache {
public:
    static SystemCache& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // Check if path is in system/safe cache
    bool IsSystemPath(const std::wstring& path);
    bool IsUserWhitelistedPath(const std::wstring& path);
    
    // Manual cache refresh (thread-safe, non-blocking)
    void RequestCacheRefresh();
    bool IsCacheRefreshing() const { return m_refreshing.load(); }
    
    // Load user whitelist
    bool LoadUserWhitelist();
    
private:
    SystemCache() = default;
    
    void StartEventMonitoring();
    void OnSystemUpdateCompleted();
    void RefreshCacheThread();
    
    // Windows: SCM notifications
    void MonitorWindowsUpdate();
    
    // Linux: inotify for package managers
    void MonitorLinuxPackages();
    
    std::unordered_set<std::wstring> m_systemPaths;
    std::vector<std::wstring> m_userWhitelist;
    std::mutex m_cacheMutex;
    std::atomic<bool> m_refreshing{false};
    std::atomic<bool> m_refreshQueued{false};
    std::unique_ptr<std::thread> m_monitorThread;
    std::atomic<bool> m_running{false};
    
    // Fallback safe paths
    static const std::vector<std::wstring> SYSTEM_SAFE_PATHS;
};

// ============================================
// Task 4: Privilege Detection
// ============================================
class PrivilegeChecker {
public:
    enum class PrivilegeLevel {
        Full,       // Admin/root with all capabilities
        Limited,    // Running without admin
        Minimal     // Heavily restricted
    };
    
    struct Capabilities {
        bool canTerminateProcesses;
        bool canQuarantine;
        bool canFilterNetwork;
        bool canModifyRegistry;
        bool canAccessKernel;
    };
    
    static PrivilegeLevel GetCurrentLevel();
    static Capabilities GetCapabilities();
    static bool HasSeDebugPrivilege();  // Windows
    static bool HasCapSysAdmin();       // Linux
    
    // Restart with elevation
    static bool RestartElevated();
};

// ============================================
// Task 5: Atomic Cert Whitelisting
// ============================================
class CertTrustManager {
public:
    static CertTrustManager& Instance();
    
    struct TrustedCert {
        std::wstring thumbprint;
        std::wstring serialNumber;
        std::wstring publisher;
        std::wstring firstSeenHash;
        int64_t addedDate;
    };
    
    // Add certificate to trust store (atomic operation)
    bool TrustCertificate(const std::wstring& filePath, 
                          const std::wstring& thumbprint,
                          const std::wstring& serial,
                          const std::wstring& publisher);
    
    // Check if cert is trusted
    bool IsCertTrusted(const std::wstring& thumbprint);
    
    // Verify file hasn't changed since trust was granted (TOCTOU protection)
    bool VerifyFileIntegrity(const std::wstring& filePath, const std::wstring& thumbprint);
    
    // Get all trusted certs
    std::vector<TrustedCert> GetTrustedCerts();
    
private:
    CertTrustManager() = default;
    
    bool InitializeDatabase();
    
    std::mutex m_mutex;
};

// ============================================
// Task 6: Installation Safety Valve
// ============================================
class ConfigManager {
public:
    static ConfigManager& Instance();
    
    enum class ProtectionMode {
        Monitoring,  // Log only, allow everything
        Balanced,    // Block known threats, prompt for unknown
        ZeroTrust    // Block ALL unsigned/unknown
    };
    
    struct Config {
        ProtectionMode mode;
        int64_t installDate;
        int64_t modeLockedUntil;
        int sequenceNumber;
        std::vector<uint8_t> signature;  // HMAC-SHA256
    };
    
    bool Initialize();
    
    // First run detection and setup
    bool IsFirstRun();
    bool SetupFirstRun(ProtectionMode initialMode);
    
    // Mode management
    ProtectionMode GetCurrentMode();
    bool SetMode(ProtectionMode mode);
    bool IsModeLocked();
    
    // Check if monitoring period expired (auto-upgrade)
    void CheckModeExpiry();
    
    // Anti-tamper
    bool VerifyConfigIntegrity();
    
private:
    ConfigManager() = default;
    
    bool LoadConfig();
    bool SaveConfig();
    bool GenerateHmacKey();
    std::vector<uint8_t> ComputeHmac(const Config& config);
    bool ProtectConfigFile();
    
    Config m_config;
    std::vector<uint8_t> m_hmacKey;
    std::mutex m_mutex;
    
    static constexpr int MONITORING_PERIOD_DAYS = 7;
};

// ============================================
// Task 7: Smart Kill Loop
// ============================================
class ProcessTerminator {
public:
    enum class TerminationResult {
        Success,
        GracefulExit,
        ForcedKill,
        KernelKill,
        Failed,
        PossibleRootkit
    };
    
    struct TerminationOptions {
        bool showProgress = true;
        int gracefulTimeoutMs = 5000;
        bool useKernelFallback = true;
    };
    
    using ProgressCallback = std::function<void(const std::wstring& status, int remainingSeconds)>;
    
    // Terminate process with smart escalation
    static TerminationResult Terminate(DWORD pid, 
                                        const TerminationOptions& options = {},
                                        ProgressCallback progressCb = nullptr);
    
private:
    static bool GracefulShutdown(DWORD pid);
    static bool ForcedTerminate(DWORD pid);
    static bool KernelTerminate(DWORD pid);
    static bool IsProcessRunning(DWORD pid);
};

// ============================================
// Task 8: OS-Aware Integrity
// ============================================
class OSIntegrity {
public:
    struct SystemStatus {
        // OS Version
        int majorVersion;
        int minorVersion;
        int buildNumber;
        bool isWindows7;
        bool isWindows10Plus;
        bool isEOL;
        
        // Security features
        bool secureBootEnabled;
        bool hvciEnabled;
        bool selinuxEnforcing;
        bool apparmorEnabled;
        
        // Overall status
        enum class Level { Green, Yellow, Orange, Red } overallLevel;
        std::vector<std::wstring> warnings;
    };
    
    static SystemStatus CheckSystem();
    
    // Get accurate OS version (bypasses compatibility shims)
    static bool GetRealWindowsVersion(int& major, int& minor, int& build);
    
    // Check specific security features
    static bool IsSecureBootEnabled();
    static bool IsHVCIEnabled();
    static bool IsSELinuxEnforcing();
    static bool IsAppArmorEnabled();
    
    // Recommendations
    static std::vector<std::wstring> GetSecurityRecommendations();
};

} // namespace Security
