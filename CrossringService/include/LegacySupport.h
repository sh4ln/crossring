#pragma once
#include "Common.h"
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

// Windows 7/8 fallback process monitor using WMI
class WmiProcessMonitor {
public:
    static WmiProcessMonitor& Instance();
    
    using ProcessCallback = std::function<void(const ProcessEvent&)>;
    
    bool Start(ProcessCallback callback);
    void Stop();
    bool IsRunning() const { return m_running.load(); }
    
    // Check if WMI should be used (Windows < 10)
    static bool ShouldUseWmi();
    
private:
    WmiProcessMonitor() = default;
    ~WmiProcessMonitor();
    WmiProcessMonitor(const WmiProcessMonitor&) = delete;
    WmiProcessMonitor& operator=(const WmiProcessMonitor&) = delete;
    
    bool InitializeCom();
    bool ConnectToWmi();
    void MonitorThread();
    
    ProcessCallback m_callback;
    std::atomic<bool> m_running{false};
    std::unique_ptr<std::thread> m_monitorThread;
    
    IWbemLocator* m_pLocator = nullptr;
    IWbemServices* m_pServices = nullptr;
    IEnumWbemClassObject* m_pEnumerator = nullptr;
};

// Script scanner for systems without AMSI (Windows 7/8)
class LegacyScriptScanner {
public:
    static LegacyScriptScanner& Instance();
    
    bool Initialize();
    void Shutdown();
    
    enum class ScanResult {
        Clean,
        Suspicious,
        Malicious
    };
    
    // Scan script content using pattern matching
    ScanResult ScanScript(const std::wstring& content, const std::wstring& scriptType);
    ScanResult ScanFile(const std::wstring& filePath);
    
    // Detection patterns
    void LoadDefaultPatterns();
    void AddPattern(const std::wstring& pattern, bool isMalicious);
    
private:
    LegacyScriptScanner() = default;
    
    struct Pattern {
        std::wstring regex;
        bool isMalicious;
        std::wstring description;
    };
    
    std::vector<Pattern> m_patterns;
    std::mutex m_mutex;
};

// Group Policy-based whitelisting for Windows 7/8
class LegacyWhitelist {
public:
    static LegacyWhitelist& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // Enable/disable "Run only specified applications"
    bool EnableWhitelist();
    bool DisableWhitelist();
    bool IsEnabled();
    
    // Manage allowed applications
    bool AddAllowedApp(const std::wstring& exeName);
    bool RemoveAllowedApp(const std::wstring& exeName);
    std::vector<std::wstring> GetAllowedApps();
    
private:
    LegacyWhitelist() = default;
    
    bool SetRegistryValue(const std::wstring& valueName, DWORD value);
    bool SetRegistryString(const std::wstring& keyPath, const std::wstring& valueName, const std::wstring& value);
    
    static constexpr const wchar_t* POLICY_KEY = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
    static constexpr const wchar_t* RESTRICT_RUN_KEY = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\RestrictRun";
};
