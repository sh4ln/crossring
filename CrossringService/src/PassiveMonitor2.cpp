// CROSSRING Passive Monitoring Implementation - Part 2
// Tasks 12, 13, 14: Backup/Recovery, Performance Limits, Privacy

#include "PassiveMonitor.h"
#include "HashUtil.h"
#include <fstream>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <winsock2.h>
#include <Windows.h>
#include <Psapi.h>
#include <Pdh.h>
#include <aclapi.h>
#include <iphlpapi.h>
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace PassiveMonitor {

// ============================================
// Task 12: Backup & Recovery Safety Net
// ============================================

BackupManager& BackupManager::Instance() {
    static BackupManager instance;
    return instance;
}

BackupManager::BackupManager() {
    // Ensure quarantine directory exists
#ifdef _WIN32
    fs::create_directories(QUARANTINE_DIR);
#else
    fs::create_directories("/var/lib/crossring/quarantine");
#endif
}

std::wstring BackupManager::GetQuarantinePath(const std::wstring& sha256) {
    return std::wstring(QUARANTINE_DIR) + L"\\" + sha256;
}

bool BackupManager::QuarantineFile(const std::wstring& path, const std::wstring& reason) {
    try {
        // Compute hash
        std::wstring hash = HashUtil::ComputeSHA256(path);
        if (hash.empty()) return false;
        
        // Create quarantine directory for this file
        std::wstring quarantineDir = GetQuarantinePath(hash);
        fs::create_directories(quarantineDir);
        
        // Move file to quarantine
        std::wstring destPath = quarantineDir + L"\\original.exe";
        fs::copy(path, destPath, fs::copy_options::overwrite_existing);
        
        // Save metadata
        QuarantineEntry entry;
        entry.originalPath = path;
        entry.sha256 = hash;
        entry.reason = reason;
        entry.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
#ifdef _WIN32
        // Backup original ACL
        PSECURITY_DESCRIPTOR pSD = nullptr;
        PACL pDacl = nullptr;
        if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                   nullptr, nullptr, &pDacl, nullptr, &pSD) == ERROR_SUCCESS) {
            if (pDacl) {
                entry.originalAcl.resize(pDacl->AclSize);
                memcpy(entry.originalAcl.data(), pDacl, pDacl->AclSize);
            }
            if (pSD) LocalFree(pSD);
        }
#endif
        
        // Save metadata JSON
        std::wstring metaPath = quarantineDir + L"\\quarantine.json";
        std::wofstream metaFile(metaPath);
        if (metaFile) {
            metaFile << L"{\n";
            metaFile << L"  \"originalPath\": \"" << entry.originalPath << L"\",\n";
            metaFile << L"  \"sha256\": \"" << entry.sha256 << L"\",\n";
            metaFile << L"  \"reason\": \"" << entry.reason << L"\",\n";
            metaFile << L"  \"timestamp\": " << entry.timestamp << L"\n";
            metaFile << L"}\n";
        }
        
        // Delete original file
        fs::remove(path);
        
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool BackupManager::RestoreFile(const std::wstring& sha256) {
    try {
        std::wstring quarantineDir = GetQuarantinePath(sha256);
        std::wstring quarantinedFile = quarantineDir + L"\\original.exe";
        std::wstring metaPath = quarantineDir + L"\\quarantine.json";
        
        // Read metadata to get original path
        std::wifstream metaFile(metaPath);
        if (!metaFile) return false;
        
        std::wstringstream buffer;
        buffer << metaFile.rdbuf();
        std::wstring json = buffer.str();
        
        // Parse original path (simple extraction)
        size_t pathStart = json.find(L"\"originalPath\": \"") + 17;
        size_t pathEnd = json.find(L"\"", pathStart);
        std::wstring originalPath = json.substr(pathStart, pathEnd - pathStart);
        
        // Restore file
        fs::copy(quarantinedFile, originalPath, fs::copy_options::overwrite_existing);
        
        // Cleanup quarantine
        fs::remove_all(quarantineDir);
        
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

std::vector<BackupManager::QuarantineEntry> BackupManager::GetQuarantinedFiles() {
    std::vector<QuarantineEntry> entries;
    
    try {
        for (const auto& dir : fs::directory_iterator(QUARANTINE_DIR)) {
            if (!dir.is_directory()) continue;
            
            std::wstring metaPath = dir.path().wstring() + L"\\quarantine.json";
            std::wifstream metaFile(metaPath);
            if (!metaFile) continue;
            
            QuarantineEntry entry;
            entry.sha256 = dir.path().filename().wstring();
            
            // Parse JSON (simple)
            std::wstringstream buffer;
            buffer << metaFile.rdbuf();
            std::wstring json = buffer.str();
            
            // Extract fields
            size_t pathStart = json.find(L"\"originalPath\": \"") + 17;
            size_t pathEnd = json.find(L"\"", pathStart);
            entry.originalPath = json.substr(pathStart, pathEnd - pathStart);
            
            size_t reasonStart = json.find(L"\"reason\": \"") + 11;
            size_t reasonEnd = json.find(L"\"", reasonStart);
            entry.reason = json.substr(reasonStart, reasonEnd - reasonStart);
            
            entries.push_back(entry);
        }
    }
    catch (const std::exception&) {}
    
    return entries;
}

void BackupManager::BackupConfig() {
#ifdef _WIN32
    std::wstring configPath = L"C:\\ProgramData\\CROSSRING\\config.xml";
#else
    std::wstring configPath = L"/etc/crossring/config.xml";
#endif
    
    if (!fs::exists(configPath)) return;
    
    // Create timestamped backup
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    wchar_t timestamp[64];
    std::tm tm;
    localtime_s(&tm, &time);
    std::wcsftime(timestamp, sizeof(timestamp) / sizeof(wchar_t), 
                  L"%Y%m%d_%H%M%S", &tm);
    
    std::wstring backupPath = configPath + L".backup." + timestamp;
    
    try {
        fs::copy(configPath, backupPath, fs::copy_options::overwrite_existing);
        PruneOldBackups(5);  // Keep only last 5
    }
    catch (const std::exception&) {}
}

void BackupManager::PruneOldBackups(int maxBackups) {
#ifdef _WIN32
    std::wstring configDir = L"C:\\ProgramData\\CROSSRING";
#else
    std::wstring configDir = L"/etc/crossring";
#endif
    
    std::vector<fs::path> backups;
    
    for (const auto& entry : fs::directory_iterator(configDir)) {
        if (entry.path().wstring().find(L".backup.") != std::wstring::npos) {
            backups.push_back(entry.path());
        }
    }
    
    // Sort by modification time (oldest first)
    std::sort(backups.begin(), backups.end(), [](const auto& a, const auto& b) {
        return fs::last_write_time(a) < fs::last_write_time(b);
    });
    
    // Delete oldest if over limit
    while (backups.size() > static_cast<size_t>(maxBackups)) {
        fs::remove(backups.front());
        backups.erase(backups.begin());
    }
}

bool BackupManager::RestoreConfigFromBackup() {
#ifdef _WIN32
    std::wstring configDir = L"C:\\ProgramData\\CROSSRING";
    std::wstring configPath = L"C:\\ProgramData\\CROSSRING\\config.xml";
#else
    std::wstring configDir = L"/etc/crossring";
    std::wstring configPath = L"/etc/crossring/config.xml";
#endif
    
    // Find most recent backup
    fs::path newestBackup;
    fs::file_time_type newestTime;
    
    for (const auto& entry : fs::directory_iterator(configDir)) {
        if (entry.path().wstring().find(L".backup.") != std::wstring::npos) {
            if (newestBackup.empty() || entry.last_write_time() > newestTime) {
                newestBackup = entry.path();
                newestTime = entry.last_write_time();
            }
        }
    }
    
    if (newestBackup.empty()) return false;
    
    try {
        fs::copy(newestBackup, configPath, fs::copy_options::overwrite_existing);
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool BackupManager::CheckFactoryResetRequest() {
#ifdef _WIN32
    return GetFileAttributesW(FACTORY_RESET_FILE) != INVALID_FILE_ATTRIBUTES;
#else
    return fs::exists("/tmp/crossring_factory_reset");
#endif
}

void BackupManager::PerformFactoryReset() {
#ifdef _WIN32
    std::wstring dataDir = L"C:\\ProgramData\\CROSSRING";
    DeleteFileW(FACTORY_RESET_FILE);
#else
    std::wstring dataDir = L"/var/lib/crossring";
    fs::remove("/tmp/crossring_factory_reset");
#endif
    
    // Delete all configs, whitelists, quarantine
    try {
        fs::remove_all(dataDir);
        fs::create_directories(dataDir);
    }
    catch (const std::exception&) {}
}

// ============================================
// Task 13: Performance & Resource Limits
// ============================================

ResourceLimiter& ResourceLimiter::Instance() {
    static ResourceLimiter instance;
    return instance;
}

void ResourceLimiter::Initialize() {
    m_lastActivity = std::chrono::steady_clock::now();
    SetLowIoPriority();
}

void ResourceLimiter::SetLoadLevel(LoadLevel level) {
    m_loadLevel = level;
}

double ResourceLimiter::GetProcessCpuUsage() {
#ifdef _WIN32
    static ULARGE_INTEGER lastCPU, lastSysCPU, lastUserCPU;
    static int numProcessors;
    static HANDLE self = GetCurrentProcess();
    static bool initialized = false;
    
    if (!initialized) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        numProcessors = sysInfo.dwNumberOfProcessors;
        
        FILETIME ftime, fsys, fuser;
        GetSystemTimeAsFileTime(&ftime);
        memcpy(&lastCPU, &ftime, sizeof(FILETIME));
        
        GetProcessTimes(self, &ftime, &ftime, &fsys, &fuser);
        memcpy(&lastSysCPU, &fsys, sizeof(FILETIME));
        memcpy(&lastUserCPU, &fuser, sizeof(FILETIME));
        
        initialized = true;
        return 0.0;
    }
    
    FILETIME ftime, fsys, fuser;
    ULARGE_INTEGER now, sys, user;
    
    GetSystemTimeAsFileTime(&ftime);
    memcpy(&now, &ftime, sizeof(FILETIME));
    
    GetProcessTimes(self, &ftime, &ftime, &fsys, &fuser);
    memcpy(&sys, &fsys, sizeof(FILETIME));
    memcpy(&user, &fuser, sizeof(FILETIME));
    
    double percent = (sys.QuadPart - lastSysCPU.QuadPart) +
                     (user.QuadPart - lastUserCPU.QuadPart);
    percent /= (now.QuadPart - lastCPU.QuadPart);
    percent /= numProcessors;
    percent *= 100;
    
    lastCPU = now;
    lastSysCPU = sys;
    lastUserCPU = user;
    
    return percent;
#else
    return 0.0;  // TODO: Linux implementation
#endif
}

bool ResourceLimiter::ShouldPauseTasks() {
    return m_tasksPaused.load();
}

void ResourceLimiter::ThrottleIfNeeded() {
    double cpu = GetProcessCpuUsage();
    double limit;
    
    switch (m_loadLevel.load()) {
        case LoadLevel::Threat:
            limit = CPU_LIMIT_THREAT;
            break;
        case LoadLevel::UserScan:
            limit = CPU_LIMIT_USERSCAN;
            break;
        default:
            limit = CPU_LIMIT_NORMAL;
    }
    
    if (cpu > limit) {
        m_tasksPaused = true;
    } else if (cpu < (limit - 2.0)) {
        m_tasksPaused = false;
    }
}

bool ResourceLimiter::IsWithinMemoryBudget() {
    return GetCurrentMemoryUsage() <= MEMORY_LIMIT_MB;
}

size_t ResourceLimiter::GetCurrentMemoryUsage() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024 * 1024);  // Convert to MB
    }
#else
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return usage.ru_maxrss / 1024;  // Convert KB to MB
    }
#endif
    return 0;
}

void ResourceLimiter::ClearCachesIfNeeded() {
    if (!IsWithinMemoryBudget()) {
        // Clear in-memory caches
        // This would interface with other components
    }
}

void ResourceLimiter::SetLowIoPriority() {
#ifdef _WIN32
    SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
    // Or use SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
#else
    // ionice equivalent
    setpriority(PRIO_PROCESS, 0, 10);  // Nice +10
#endif
}

bool ResourceLimiter::ShouldSkipLargeFile(size_t fileSize) {
    return fileSize > MAX_FILE_SIZE;
}

bool ResourceLimiter::IsDiskBusy() {
    // Simplified: check if >80% disk usage
    // In production, use performance counters
    return false;
}

bool ResourceLimiter::IsSystemIdle() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - m_lastActivity);
    
    return elapsed.count() >= 10;
}

void ResourceLimiter::UpdateActivityTimestamp() {
    m_lastActivity = std::chrono::steady_clock::now();
}

ResourceLimiter::Stats ResourceLimiter::GetStats() {
    Stats stats;
    stats.cpuUsage = GetProcessCpuUsage();
    stats.memoryMB = GetCurrentMemoryUsage();
    stats.isPaused = m_tasksPaused.load();
    stats.lastActivity = m_lastActivity;
    return stats;
}

// ============================================
// Task 14: Telemetry & Privacy (ZERO DATA)
// ============================================

PrivacyGuard& PrivacyGuard::Instance() {
    static PrivacyGuard instance;
    return instance;
}

PrivacyGuard::PrivacyGuard() {
#ifdef _WIN32
    m_logDir = L"C:\\ProgramData\\CROSSRING\\Logs";
#else
    m_logDir = L"/var/log/crossring";
#endif
    
    fs::create_directories(m_logDir);
    
    // Open current log file
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    wchar_t dateStr[32];
    std::tm tm;
    localtime_s(&tm, &time);
    std::wcsftime(dateStr, sizeof(dateStr) / sizeof(wchar_t), L"%Y-%m-%d", &tm);
    
    std::wstring logPath = m_logDir + L"\\crossring_" + dateStr + L".log";
    m_currentLog.open(logPath, std::ios::app);
}

bool PrivacyGuard::VerifyNoNetworkConnections() {
    // CROSSRING should NEVER initiate outbound connections
    // This function is for user verification
    
#ifdef _WIN32
    // Check if our process has any network connections
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    std::vector<uint8_t> buffer(size);
    auto* tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    
    if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        DWORD ourPid = GetCurrentProcessId();
        
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            if (tcpTable->table[i].dwOwningPid == ourPid) {
                return false;  // We have connections (should not happen)
            }
        }
    }
#endif
    
    return true;  // No connections found - good!
}

void PrivacyGuard::Log(const std::wstring& message) {
    std::lock_guard<std::mutex> lock(m_logMutex);
    
    if (!m_currentLog.is_open()) return;
    
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    char timeStr[64];
    std::tm tm;
    localtime_s(&tm, &time);
    std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm);
    
    m_currentLog << timeStr << " [INFO] ";
    
    std::string narrowMsg(message.begin(), message.end());
    m_currentLog << narrowMsg << std::endl;
}

void PrivacyGuard::LogThreat(const std::wstring& threatInfo) {
    std::lock_guard<std::mutex> lock(m_logMutex);
    
    if (!m_currentLog.is_open()) return;
    
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    char timeStr[64];
    std::tm tm2;
    localtime_s(&tm2, &time);
    std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm2);
    
    m_currentLog << timeStr << " [THREAT] ";
    
    std::string narrowMsg(threatInfo.begin(), threatInfo.end());
    m_currentLog << narrowMsg << std::endl;
    m_currentLog.flush();
}

void PrivacyGuard::RotateLogs() {
    // Delete logs older than 30 days
    auto now = std::chrono::system_clock::now();
    auto threshold = now - std::chrono::hours(24 * LOG_RETENTION_DAYS);
    
    try {
        for (const auto& entry : fs::directory_iterator(m_logDir)) {
            if (entry.path().extension() == L".log") {
                auto fileTime = entry.last_write_time();
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    fileTime - fs::file_time_type::clock::now() + now);
                
                if (sctp < threshold) {
                    // Compress instead of delete (optional)
                    fs::remove(entry.path());
                }
            }
        }
    }
    catch (const std::exception&) {}
}

bool PrivacyGuard::ExportLogsToFile(const std::wstring& outputPath) {
    try {
        std::wofstream output(outputPath);
        if (!output) return false;
        
        output << L"CROSSRING Log Export\n";
        output << L"====================\n\n";
        
        for (const auto& entry : fs::directory_iterator(m_logDir)) {
            if (entry.path().extension() == L".log") {
                std::wifstream logFile(entry.path());
                if (logFile) {
                    output << L"--- " << entry.path().filename().wstring() << L" ---\n";
                    output << logFile.rdbuf();
                    output << L"\n\n";
                }
            }
        }
        
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

std::wstring PrivacyGuard::GetAnonymizedThreatHashes() {
    std::wstringstream ss;
    ss << L"# CROSSRING Anonymous Threat Hashes\n";
    ss << L"# Share these with the community if you wish\n\n";
    
    // Collect threat hashes from logs (hashes only, no PII)
    try {
        for (const auto& entry : fs::directory_iterator(m_logDir)) {
            if (entry.path().extension() == L".log") {
                std::wifstream logFile(entry.path());
                std::wstring line;
                
                while (std::getline(logFile, line)) {
                    // Extract SHA256 hashes (64 hex chars)
                    for (size_t i = 0; i + 64 <= line.size(); i++) {
                        bool isHash = true;
                        for (size_t j = 0; j < 64; j++) {
                            wchar_t c = line[i + j];
                            if (!isxdigit(c)) {
                                isHash = false;
                                break;
                            }
                        }
                        if (isHash) {
                            ss << line.substr(i, 64) << L"\n";
                            i += 63;
                        }
                    }
                }
            }
        }
    }
    catch (const std::exception&) {}
    
    return ss.str();
}

// ============================================
// Aggregate Manager
// ============================================

PassiveSecurityManager& PassiveSecurityManager::Instance() {
    static PassiveSecurityManager instance;
    return instance;
}

bool PassiveSecurityManager::InitializeAll() {
    InjectionDetector::Instance().Initialize();
    ResourceLimiter::Instance().Initialize();
    
    return true;
}

void PassiveSecurityManager::ShutdownAll() {
    InjectionDetector::Instance().Shutdown();
}

void PassiveSecurityManager::RunPeriodicChecks() {
    // Run kernel integrity scan (every 5 minutes)
    auto indicators = KernelIntegrity::Instance().Scan();
    
    if (indicators.driverSigningDisabled) {
        PrivacyGuard::Instance().LogThreat(L"Driver signing disabled");
    }
    
    if (!indicators.hiddenPids.empty()) {
        std::wstringstream ss;
        ss << L"Hidden processes detected: ";
        for (DWORD pid : indicators.hiddenPids) {
            ss << pid << L" ";
        }
        PrivacyGuard::Instance().LogThreat(ss.str());
    }
    
    if (indicators.syscallHooked) {
        PrivacyGuard::Instance().LogThreat(L"Syscall hook detected");
    }
    
    // Check resource limits
    ResourceLimiter::Instance().ThrottleIfNeeded();
    ResourceLimiter::Instance().ClearCachesIfNeeded();
    
    // Rotate logs if needed
    PrivacyGuard::Instance().RotateLogs();
}

PassiveSecurityManager::SystemHealth PassiveSecurityManager::GetSystemHealth() {
    SystemHealth health = {};
    
    auto indicators = KernelIntegrity::Instance().Scan();
    health.kernelIntegrityOk = !indicators.driverSigningDisabled && !indicators.syscallHooked;
    health.noHiddenProcesses = indicators.hiddenPids.empty();
    
    auto stats = ResourceLimiter::Instance().GetStats();
    health.performanceOk = stats.cpuUsage < 10.0 && stats.memoryMB < 150;
    
    return health;
}

} // namespace PassiveMonitor
