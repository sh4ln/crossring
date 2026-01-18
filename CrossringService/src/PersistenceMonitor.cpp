// CROSSRING - Persistence Monitor Implementation
#include "PersistenceMonitor.h"
#include <shlobj.h>

const std::vector<std::wstring> PersistenceMonitor::REGISTRY_RUN_KEYS = {
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
};

PersistenceMonitor::~PersistenceMonitor() {
    Stop();
}

PersistenceMonitor& PersistenceMonitor::Instance() {
    static PersistenceMonitor instance;
    return instance;
}

bool PersistenceMonitor::Start() {
    if (m_running.load()) return true;
    
    TakeBaseline();
    m_running = true;
    m_monitorThread = std::make_unique<std::thread>(&PersistenceMonitor::MonitorThread, this);
    return true;
}

void PersistenceMonitor::Stop() {
    m_running = false;
    if (m_monitorThread && m_monitorThread->joinable()) {
        m_monitorThread->join();
    }
}

void PersistenceMonitor::MonitorThread() {
    while (m_running.load()) {
        auto changes = DetectChanges();
        for (const auto& entry : changes) {
            if (m_callback) m_callback(entry);
        }
        
        for (DWORD i = 0; i < SCAN_INTERVAL_MS / 1000 && m_running.load(); ++i) {
            Sleep(1000);
        }
    }
}

void PersistenceMonitor::TakeBaseline() {
    std::lock_guard<std::mutex> lock(m_baselineMutex);
    m_baseline = GetCurrentPersistence();
}

std::vector<PersistenceMonitor::PersistenceEntry> PersistenceMonitor::GetCurrentPersistence() {
    std::vector<PersistenceEntry> entries;
    
    auto reg = ScanRegistryRun();
    entries.insert(entries.end(), reg.begin(), reg.end());
    
    auto startup = ScanStartupFolders();
    entries.insert(entries.end(), startup.begin(), startup.end());
    
    auto services = ScanServices();
    entries.insert(entries.end(), services.begin(), services.end());
    
    return entries;
}

std::vector<PersistenceMonitor::PersistenceEntry> PersistenceMonitor::DetectChanges() {
    std::vector<PersistenceEntry> changes;
    auto current = GetCurrentPersistence();
    
    std::lock_guard<std::mutex> lock(m_baselineMutex);
    
    // Find new entries
    for (const auto& entry : current) {
        bool found = false;
        for (const auto& base : m_baseline) {
            if (entry.location == base.location && entry.value == base.value) {
                found = true;
                break;
            }
        }
        if (!found) {
            PersistenceEntry newEntry = entry;
            newEntry.isNew = true;
            newEntry.timestamp = GetCurrentTimestamp();
            changes.push_back(newEntry);
        }
    }
    
    // Update baseline
    m_baseline = current;
    
    return changes;
}

std::vector<PersistenceMonitor::PersistenceEntry> PersistenceMonitor::ScanRegistryRun() {
    std::vector<PersistenceEntry> entries;
    
    HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    
    for (HKEY root : roots) {
        for (const auto& keyPath : REGISTRY_RUN_KEYS) {
            HKEY hKey;
            if (RegOpenKeyExW(root, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD index = 0;
                wchar_t valueName[256];
                DWORD valueNameLen = 256;
                BYTE valueData[1024];
                DWORD valueDataLen = 1024;
                DWORD valueType;
                
                while (RegEnumValueW(hKey, index++, valueName, &valueNameLen, nullptr,
                                      &valueType, valueData, &valueDataLen) == ERROR_SUCCESS) {
                    if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                        PersistenceEntry entry;
                        entry.type = L"Registry";
                        entry.location = (root == HKEY_LOCAL_MACHINE ? L"HKLM\\" : L"HKCU\\") + keyPath + L"\\" + valueName;
                        entry.value = reinterpret_cast<wchar_t*>(valueData);
                        entries.push_back(entry);
                    }
                    valueNameLen = 256;
                    valueDataLen = 1024;
                }
                RegCloseKey(hKey);
            }
        }
    }
    
    return entries;
}

std::vector<PersistenceMonitor::PersistenceEntry> PersistenceMonitor::ScanRegistryRunOnce() {
    // Similar to ScanRegistryRun but for RunOnce keys
    return {};
}

std::vector<PersistenceMonitor::PersistenceEntry> PersistenceMonitor::ScanStartupFolders() {
    std::vector<PersistenceEntry> entries;
    
    wchar_t path[MAX_PATH];
    
    // User startup folder
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, path))) {
        WIN32_FIND_DATAW fd;
        std::wstring searchPath = std::wstring(path) + L"\\*";
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    PersistenceEntry entry;
                    entry.type = L"StartupFolder";
                    entry.location = std::wstring(path) + L"\\" + fd.cFileName;
                    entry.value = fd.cFileName;
                    entries.push_back(entry);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
    
    // Common startup folder
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, path))) {
        WIN32_FIND_DATAW fd;
        std::wstring searchPath = std::wstring(path) + L"\\*";
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    PersistenceEntry entry;
                    entry.type = L"StartupFolder";
                    entry.location = std::wstring(path) + L"\\" + fd.cFileName;
                    entry.value = fd.cFileName;
                    entries.push_back(entry);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
    
    return entries;
}

std::vector<PersistenceMonitor::PersistenceEntry> PersistenceMonitor::ScanServices() {
    std::vector<PersistenceEntry> entries;
    
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) return entries;
    
    DWORD bytesNeeded = 0, servicesReturned = 0;
    EnumServicesStatusExW(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &servicesReturned, nullptr, nullptr);
    
    std::vector<BYTE> buffer(bytesNeeded);
    if (EnumServicesStatusExW(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, buffer.data(), bytesNeeded,
                               &bytesNeeded, &servicesReturned, nullptr, nullptr)) {
        auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for (DWORD i = 0; i < servicesReturned; i++) {
            // Only non-Microsoft services
            SC_HANDLE svc = OpenServiceW(scManager, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (svc) {
                DWORD needed = 0;
                QueryServiceConfigW(svc, nullptr, 0, &needed);
                std::vector<BYTE> configBuf(needed);
                if (QueryServiceConfigW(svc, reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuf.data()),
                                         needed, &needed)) {
                    auto* config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuf.data());
                    std::wstring binPath = config->lpBinaryPathName ? config->lpBinaryPathName : L"";
                    std::transform(binPath.begin(), binPath.end(), binPath.begin(), ::towlower);
                    
                    // Skip Windows services
                    if (binPath.find(L"c:\\windows\\") == std::wstring::npos) {
                        PersistenceEntry entry;
                        entry.type = L"Service";
                        entry.location = services[i].lpServiceName;
                        entry.value = config->lpBinaryPathName ? config->lpBinaryPathName : L"";
                        entries.push_back(entry);
                    }
                }
                CloseServiceHandle(svc);
            }
        }
    }
    
    CloseServiceHandle(scManager);
    return entries;
}

std::vector<PersistenceMonitor::PersistenceEntry> PersistenceMonitor::ScanScheduledTasks() {
    // Would use Task Scheduler COM API
    return {};
}
