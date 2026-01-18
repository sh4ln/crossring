// CROSSRING - WMI Process Monitor for Windows 7/8
#include "LegacySupport.h"
#include "HashUtil.h"
#include <comdef.h>
#include <algorithm>
#include <regex>

// ============ WmiProcessMonitor Implementation ============

WmiProcessMonitor::~WmiProcessMonitor() {
    Stop();
}

WmiProcessMonitor& WmiProcessMonitor::Instance() {
    static WmiProcessMonitor instance;
    return instance;
}

bool WmiProcessMonitor::ShouldUseWmi() {
    // Use WMI on Windows 7/8 (version 6.x)
    OSVERSIONINFOEXW osvi = { sizeof(osvi) };
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    auto RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlGetVersion");
    if (RtlGetVersion) {
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
        return osvi.dwMajorVersion < 10;
    }
    return false;
}

bool WmiProcessMonitor::InitializeCom() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return false;
    
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);
    
    return SUCCEEDED(hr) || hr == RPC_E_TOO_LATE;
}

bool WmiProcessMonitor::ConnectToWmi() {
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (void**)&m_pLocator);
    if (FAILED(hr)) return false;
    
    hr = m_pLocator->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr,
        nullptr, 0, nullptr, nullptr, &m_pServices);
    if (FAILED(hr)) return false;
    
    hr = CoSetProxyBlanket(m_pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
        nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE);
    
    return SUCCEEDED(hr);
}

bool WmiProcessMonitor::Start(ProcessCallback callback) {
    if (m_running.load()) return true;
    
    m_callback = callback;
    
    if (!InitializeCom()) return false;
    if (!ConnectToWmi()) return false;
    
    m_running = true;
    m_monitorThread = std::make_unique<std::thread>(&WmiProcessMonitor::MonitorThread, this);
    return true;
}

void WmiProcessMonitor::Stop() {
    m_running = false;
    if (m_monitorThread && m_monitorThread->joinable()) {
        m_monitorThread->join();
    }
    
    if (m_pEnumerator) { m_pEnumerator->Release(); m_pEnumerator = nullptr; }
    if (m_pServices) { m_pServices->Release(); m_pServices = nullptr; }
    if (m_pLocator) { m_pLocator->Release(); m_pLocator = nullptr; }
    
    CoUninitialize();
}

void WmiProcessMonitor::MonitorThread() {
    // Subscribe to process creation events
    IUnsecuredApartment* pUnsecApp = nullptr;
    IWbemObjectSink* pSink = nullptr;
    
    HRESULT hr = m_pServices->ExecNotificationQueryAsync(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT * FROM Win32_ProcessStartTrace"),
        WBEM_FLAG_SEND_STATUS, nullptr, nullptr);
    
    if (FAILED(hr)) {
        // Fallback to polling
        while (m_running.load()) {
            hr = m_pServices->ExecQuery(
                _bstr_t(L"WQL"),
                _bstr_t(L"SELECT ProcessId, Name, ParentProcessId, ExecutablePath FROM Win32_Process"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &m_pEnumerator);
            
            if (SUCCEEDED(hr) && m_pEnumerator) {
                IWbemClassObject* pclsObj = nullptr;
                ULONG uReturn = 0;
                
                while (m_pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
                    VARIANT vtPid, vtName, vtParent, vtPath;
                    
                    hr = pclsObj->Get(L"ProcessId", 0, &vtPid, nullptr, nullptr);
                    hr = pclsObj->Get(L"Name", 0, &vtName, nullptr, nullptr);
                    hr = pclsObj->Get(L"ParentProcessId", 0, &vtParent, nullptr, nullptr);
                    hr = pclsObj->Get(L"ExecutablePath", 0, &vtPath, nullptr, nullptr);
                    
                    if (m_callback && vtPath.vt == VT_BSTR) {
                        ProcessEvent event;
                        event.timestamp = GetCurrentTimestamp();
                        event.pid = vtPid.ulVal;
                        event.parentPid = vtParent.ulVal;
                        event.imagePath = vtPath.bstrVal ? vtPath.bstrVal : L"";
                        event.hashSha256 = HashUtil::ComputeSHA256(event.imagePath);
                        
                        m_callback(event);
                    }
                    
                    VariantClear(&vtPid);
                    VariantClear(&vtName);
                    VariantClear(&vtParent);
                    VariantClear(&vtPath);
                    pclsObj->Release();
                }
                m_pEnumerator->Release();
                m_pEnumerator = nullptr;
            }
            
            Sleep(2000); // Poll every 2 seconds
        }
    }
}

// ============ LegacyScriptScanner Implementation ============

LegacyScriptScanner& LegacyScriptScanner::Instance() {
    static LegacyScriptScanner instance;
    return instance;
}

bool LegacyScriptScanner::Initialize() {
    LoadDefaultPatterns();
    return true;
}

void LegacyScriptScanner::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_patterns.clear();
}

void LegacyScriptScanner::LoadDefaultPatterns() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_patterns.clear();
    
    // Malicious patterns (definite threats)
    m_patterns.push_back({ L"Invoke-Mimikatz", true, L"Credential theft tool" });
    m_patterns.push_back({ L"Empire", true, L"Post-exploitation framework" });
    m_patterns.push_back({ L"Invoke-Shellcode", true, L"Shellcode injection" });
    m_patterns.push_back({ L"DumpCreds", true, L"Credential dump" });
    m_patterns.push_back({ L"Get-Keystrokes", true, L"Keylogger" });
    m_patterns.push_back({ L"Invoke-DllInjection", true, L"DLL injection" });
    m_patterns.push_back({ L"Invoke-TokenManipulation", true, L"Token manipulation" });
    m_patterns.push_back({ L"Invoke-PowerShellTcp", true, L"Reverse shell" });
    m_patterns.push_back({ L"Invoke-ReflectivePEInjection", true, L"PE injection" });
    m_patterns.push_back({ L"net user.*\\/add", true, L"Adding user account" });
    m_patterns.push_back({ L"reg add.*\\\\Run", true, L"Registry persistence" });
    
    // Suspicious patterns (may be legitimate but worth flagging)
    m_patterns.push_back({ L"-enc[odedcommand]*\\s+[A-Za-z0-9+/=]{20,}", false, L"Encoded PowerShell" });
    m_patterns.push_back({ L"\\[System\\.Convert\\]::FromBase64String", false, L"Base64 decode" });
    m_patterns.push_back({ L"New-Object\\s+Net\\.WebClient", false, L"Download capability" });
    m_patterns.push_back({ L"DownloadString|DownloadFile", false, L"Remote download" });
    m_patterns.push_back({ L"Invoke-Expression|IEX", false, L"Dynamic execution" });
    m_patterns.push_back({ L"\\$env:TEMP|\\$env:APPDATA", false, L"Temp folder access" });
    m_patterns.push_back({ L"Hidden|NonInteractive", false, L"Hidden execution" });
    m_patterns.push_back({ L"bypass|unrestricted", false, L"Policy bypass" });
}

void LegacyScriptScanner::AddPattern(const std::wstring& pattern, bool isMalicious) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_patterns.push_back({ pattern, isMalicious, L"Custom rule" });
}

LegacyScriptScanner::ScanResult LegacyScriptScanner::ScanScript(
    const std::wstring& content, const std::wstring& scriptType) {
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::wstring lower = content;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    int suspiciousCount = 0;
    bool foundMalicious = false;
    
    for (const auto& pattern : m_patterns) {
        try {
            std::wregex rx(pattern.regex, std::regex::icase);
            if (std::regex_search(content, rx)) {
                if (pattern.isMalicious) {
                    foundMalicious = true;
                    break;
                }
                suspiciousCount++;
            }
        }
        catch (const std::regex_error&) {
            // FIX #7: Regex pattern is invalid, fall back to simple string matching
            // (Don't catch all exceptions - let memory errors propagate)
            if (lower.find(pattern.regex) != std::wstring::npos) {
                if (pattern.isMalicious) {
                    foundMalicious = true;
                    break;
                }
                suspiciousCount++;
            }
        }
    }
    
    if (foundMalicious) return ScanResult::Malicious;
    if (suspiciousCount >= 3) return ScanResult::Suspicious;
    return ScanResult::Clean;
}

LegacyScriptScanner::ScanResult LegacyScriptScanner::ScanFile(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return ScanResult::Clean;
    
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize > 10 * 1024 * 1024) { // Max 10MB
        CloseHandle(hFile);
        return ScanResult::Clean;
    }
    
    std::vector<char> buffer(fileSize + 1);
    DWORD bytesRead;
    ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);
    
    buffer[bytesRead] = 0;
    
    // Convert to wide string
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, buffer.data(), -1, nullptr, 0);
    std::wstring content(wideLen, 0);
    MultiByteToWideChar(CP_UTF8, 0, buffer.data(), -1, &content[0], wideLen);
    
    return ScanScript(content, L"file");
}

// ============ LegacyWhitelist Implementation ============

LegacyWhitelist& LegacyWhitelist::Instance() {
    static LegacyWhitelist instance;
    return instance;
}

bool LegacyWhitelist::Initialize() {
    return true;
}

void LegacyWhitelist::Shutdown() {
    // Don't disable on shutdown - let user decide
}

bool LegacyWhitelist::EnableWhitelist() {
    return SetRegistryValue(L"RestrictRun", 1);
}

bool LegacyWhitelist::DisableWhitelist() {
    return SetRegistryValue(L"RestrictRun", 0);
}

bool LegacyWhitelist::IsEnabled() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, POLICY_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    DWORD value = 0, size = sizeof(DWORD);
    RegQueryValueExW(hKey, L"RestrictRun", nullptr, nullptr, (LPBYTE)&value, &size);
    RegCloseKey(hKey);
    
    return value == 1;
}

bool LegacyWhitelist::AddAllowedApp(const std::wstring& exeName) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, RESTRICT_RUN_KEY, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    
    // Find next available index
    DWORD index = 1;
    wchar_t valueName[16];
    wchar_t valueData[MAX_PATH];
    DWORD valueDataSize = MAX_PATH;
    
    while (true) {
        swprintf_s(valueName, L"%lu", index);
        LONG result = RegQueryValueExW(hKey, valueName, nullptr, nullptr, (LPBYTE)valueData, &valueDataSize);
        if (result != ERROR_SUCCESS) break;
        if (_wcsicmp(valueData, exeName.c_str()) == 0) {
            RegCloseKey(hKey);
            return true; // Already exists
        }
        index++;
        valueDataSize = MAX_PATH;
    }
    
    swprintf_s(valueName, L"%lu", index);
    LONG result = RegSetValueExW(hKey, valueName, 0, REG_SZ,
        (LPBYTE)exeName.c_str(), (DWORD)((exeName.size() + 1) * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

bool LegacyWhitelist::RemoveAllowedApp(const std::wstring& exeName) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, RESTRICT_RUN_KEY, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    DWORD index = 1;
    wchar_t valueName[16];
    wchar_t valueData[MAX_PATH];
    DWORD valueDataSize;
    
    while (true) {
        valueDataSize = MAX_PATH;
        swprintf_s(valueName, L"%lu", index);
        if (RegQueryValueExW(hKey, valueName, nullptr, nullptr, (LPBYTE)valueData, &valueDataSize) != ERROR_SUCCESS) {
            break;
        }
        if (_wcsicmp(valueData, exeName.c_str()) == 0) {
            RegDeleteValueW(hKey, valueName);
            RegCloseKey(hKey);
            return true;
        }
        index++;
    }
    
    RegCloseKey(hKey);
    return false;
}

std::vector<std::wstring> LegacyWhitelist::GetAllowedApps() {
    std::vector<std::wstring> apps;
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, RESTRICT_RUN_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return apps;
    }
    
    DWORD index = 0;
    wchar_t valueName[256];
    DWORD valueNameSize;
    wchar_t valueData[MAX_PATH];
    DWORD valueDataSize;
    
    while (true) {
        valueNameSize = 256;
        valueDataSize = MAX_PATH * sizeof(wchar_t);
        if (RegEnumValueW(hKey, index++, valueName, &valueNameSize, nullptr, nullptr,
            (LPBYTE)valueData, &valueDataSize) != ERROR_SUCCESS) {
            break;
        }
        apps.push_back(valueData);
    }
    
    RegCloseKey(hKey);
    return apps;
}

bool LegacyWhitelist::SetRegistryValue(const std::wstring& valueName, DWORD value) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, POLICY_KEY, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    
    LONG result = RegSetValueExW(hKey, valueName.c_str(), 0, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hKey);
    
    return result == ERROR_SUCCESS;
}

bool LegacyWhitelist::SetRegistryString(const std::wstring& keyPath, 
    const std::wstring& valueName, const std::wstring& value) {
    
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    
    LONG result = RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ,
        (LPBYTE)value.c_str(), (DWORD)((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    
    return result == ERROR_SUCCESS;
}
