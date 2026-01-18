#pragma once
#include "Common.h"
#include <amsi.h>

#pragma comment(lib, "amsi.lib")

class AmsiScanner {
public:
    static AmsiScanner& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // Scan content for malicious patterns
    enum class ScanResult {
        Clean,
        Suspicious,
        Malicious,
        Error
    };
    
    struct ScriptInfo {
        std::wstring contentName;
        std::wstring content;
        DWORD pid;
        std::wstring timestamp;
    };
    
    using ScanCallback = std::function<void(const ScriptInfo&, ScanResult)>;
    
    ScanResult ScanBuffer(const void* buffer, ULONG length, const std::wstring& contentName);
    ScanResult ScanScript(const std::wstring& scriptContent, const std::wstring& scriptName);
    
    void SetCallback(ScanCallback callback) { m_callback = callback; }
    
    // Obfuscation detection
    bool DetectObfuscation(const std::wstring& content);
    bool DetectAmsiBypas(const std::wstring& content);
    
private:
    AmsiScanner() = default;
    ~AmsiScanner();
    AmsiScanner(const AmsiScanner&) = delete;
    AmsiScanner& operator=(const AmsiScanner&) = delete;
    
    HAMSICONTEXT m_context = nullptr;
    HAMSISESSION m_session = nullptr;
    ScanCallback m_callback;
    
    // Suspicious patterns
    std::vector<std::wstring> m_obfuscationPatterns;
    std::vector<std::wstring> m_bypassPatterns;
    
    void LoadPatterns();
};
