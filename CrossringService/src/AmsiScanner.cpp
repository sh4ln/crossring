// CROSSRING - AMSI Scanner Implementation
#include "AmsiScanner.h"
#include <algorithm>

AmsiScanner::~AmsiScanner() {
    Shutdown();
}

AmsiScanner& AmsiScanner::Instance() {
    static AmsiScanner instance;
    return instance;
}

bool AmsiScanner::Initialize() {
    HRESULT hr = AmsiInitialize(L"CROSSRING", &m_context);
    if (FAILED(hr)) return false;
    
    hr = AmsiOpenSession(m_context, &m_session);
    if (FAILED(hr)) {
        AmsiUninitialize(m_context);
        m_context = nullptr;
        return false;
    }
    
    LoadPatterns();
    return true;
}

void AmsiScanner::Shutdown() {
    if (m_session) {
        AmsiCloseSession(m_context, m_session);
        m_session = nullptr;
    }
    if (m_context) {
        AmsiUninitialize(m_context);
        m_context = nullptr;
    }
}

void AmsiScanner::LoadPatterns() {
    // Obfuscation patterns (common in malicious scripts)
    m_obfuscationPatterns = {
        L"-join", L"[char]", L"-replace", L"-split",
        L"frombase64", L"tobase64", L"-bxor",
        L"invoke-expression", L"iex", L".invoke(",
        L"[convert]::", L"[system.text.encoding]",
        L"gzipstream", L"deflatestream", L"memorystream"
    };
    
    // AMSI bypass patterns
    m_bypassPatterns = {
        L"amsicontext", L"amsiinitfailed", L"amsiutils",
        L"amsiscanbuffer", L"setvalue($null", L"amsi.dll",
        L"bypass", L"[ref].assembly", L"getfield(",
        L"nonpublic,static", L"patching amsi"
    };
}

AmsiScanner::ScanResult AmsiScanner::ScanBuffer(const void* buffer, ULONG length, 
                                                  const std::wstring& contentName) {
    if (!m_context || !m_session) return ScanResult::Error;
    
    AMSI_RESULT result;
    HRESULT hr = AmsiScanBuffer(m_context, const_cast<void*>(buffer), length,
                                 contentName.c_str(), m_session, &result);
    
    if (FAILED(hr)) return ScanResult::Error;
    
    if (AmsiResultIsMalware(result)) return ScanResult::Malicious;
    if (result >= AMSI_RESULT_DETECTED) return ScanResult::Suspicious;
    
    return ScanResult::Clean;
}

AmsiScanner::ScanResult AmsiScanner::ScanScript(const std::wstring& scriptContent,
                                                  const std::wstring& scriptName) {
    // First check for obfuscation and bypass attempts
    if (DetectAmsiBypas(scriptContent)) {
        if (m_callback) {
            ScriptInfo info;
            info.contentName = scriptName;
            info.content = scriptContent.substr(0, 500); // First 500 chars
            info.timestamp = GetCurrentTimestamp();
            m_callback(info, ScanResult::Malicious);
        }
        return ScanResult::Malicious;
    }
    
    if (DetectObfuscation(scriptContent)) {
        if (m_callback) {
            ScriptInfo info;
            info.contentName = scriptName;
            info.content = scriptContent.substr(0, 500);
            info.timestamp = GetCurrentTimestamp();
            m_callback(info, ScanResult::Suspicious);
        }
    }
    
    // Use Windows AMSI
    return ScanBuffer(scriptContent.c_str(), 
                      static_cast<ULONG>(scriptContent.size() * sizeof(wchar_t)),
                      scriptName);
}

bool AmsiScanner::DetectObfuscation(const std::wstring& content) {
    std::wstring lower = content;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    int score = 0;
    for (const auto& pattern : m_obfuscationPatterns) {
        if (lower.find(pattern) != std::wstring::npos) {
            score++;
        }
    }
    
    // High entropy check (lots of special characters)
    int specialCount = 0;
    for (wchar_t c : content) {
        if (!iswalnum(c) && !iswspace(c)) specialCount++;
    }
    float specialRatio = static_cast<float>(specialCount) / content.size();
    if (specialRatio > 0.3f) score += 2;
    
    return score >= 3; // Threshold
}

bool AmsiScanner::DetectAmsiBypas(const std::wstring& content) {
    std::wstring lower = content;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    for (const auto& pattern : m_bypassPatterns) {
        if (lower.find(pattern) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}
