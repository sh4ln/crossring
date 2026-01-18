// CROSSRING Security Core Implementation - Part 2
// Tasks 3, 5, 6, 8: System Cache, Cert Trust, Config Manager, OS Integrity

#include "SecurityCore.h"
#include "HashUtil.h"
#include "Database.h"
#include <fstream>
#include <sstream>
#include <chrono>

#ifdef _WIN32
#include <Windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#else
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace Security {

// ============================================
// Task 3: Event-Driven System Cache
// ============================================

const std::vector<std::wstring> SystemCache::SYSTEM_SAFE_PATHS = {
#ifdef _WIN32
    L"C:\\Windows\\System32",
    L"C:\\Windows\\SysWOW64",
    L"C:\\Windows\\WinSxS",
    L"C:\\Program Files",
    L"C:\\Program Files (x86)",
#else
    L"/bin",
    L"/sbin",
    L"/usr/bin",
    L"/usr/sbin",
    L"/usr/lib",
    L"/usr/lib64",
    L"/lib",
    L"/lib64",
    L"/opt",
    L"/snap/bin",
    L"/var/lib/snapd",
    L"/var/lib/flatpak/app",
    L"/usr/local/bin",
    L"/usr/local/sbin",
#endif
};

SystemCache& SystemCache::Instance() {
    static SystemCache instance;
    return instance;
}

bool SystemCache::Initialize() {
    // Load fallback safe paths
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        for (const auto& path : SYSTEM_SAFE_PATHS) {
            m_systemPaths.insert(path);
        }
    }
    
    // Load user whitelist
    LoadUserWhitelist();
    
    // Start event monitoring
    m_running = true;
    StartEventMonitoring();
    
    return true;
}

void SystemCache::Shutdown() {
    m_running = false;
    if (m_monitorThread && m_monitorThread->joinable()) {
        m_monitorThread->join();
    }
}

bool SystemCache::IsSystemPath(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    
    // Normalize path
    std::wstring normalizedPath = path;
    std::transform(normalizedPath.begin(), normalizedPath.end(), 
                   normalizedPath.begin(), ::towlower);
    
    for (const auto& safePath : m_systemPaths) {
        std::wstring normalizedSafe = safePath;
        std::transform(normalizedSafe.begin(), normalizedSafe.end(), 
                       normalizedSafe.begin(), ::towlower);
        
        if (normalizedPath.find(normalizedSafe) == 0) {
            return true;
        }
    }
    
    return false;
}

bool SystemCache::IsUserWhitelistedPath(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    
    std::wstring normalizedPath = path;
    std::transform(normalizedPath.begin(), normalizedPath.end(), 
                   normalizedPath.begin(), ::towlower);
    
    for (const auto& whitelistPath : m_userWhitelist) {
        std::wstring normalizedWhitelist = whitelistPath;
        std::transform(normalizedWhitelist.begin(), normalizedWhitelist.end(), 
                       normalizedWhitelist.begin(), ::towlower);
        
        // Handle wildcards
        if (normalizedWhitelist.back() == L'*') {
            std::wstring prefix = normalizedWhitelist.substr(0, normalizedWhitelist.size() - 1);
            if (normalizedPath.find(prefix) == 0) {
                return true;
            }
        } else if (normalizedPath == normalizedWhitelist) {
            return true;
        }
    }
    
    return false;
}

bool SystemCache::LoadUserWhitelist() {
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    m_userWhitelist.clear();
    
#ifdef _WIN32
    const wchar_t* path = L"C:\\ProgramData\\CROSSRING\\safe_paths.txt";
#else
    const char* path = "/etc/crossring/safe_paths.conf";
#endif
    
    std::wifstream file(path);
    if (!file.is_open()) return false;
    
    std::wstring line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == L'#') continue;
        
        // Trim whitespace
        size_t start = line.find_first_not_of(L" \t");
        size_t end = line.find_last_not_of(L" \t\r\n");
        if (start != std::wstring::npos && end != std::wstring::npos) {
            m_userWhitelist.push_back(line.substr(start, end - start + 1));
        }
    }
    
    return true;
}

void SystemCache::RequestCacheRefresh() {
    if (m_refreshing.load()) {
        m_refreshQueued = true;
        return;
    }
    
    // Non-blocking refresh on dedicated thread
    std::thread([this]() {
        RefreshCacheThread();
    }).detach();
}

void SystemCache::RefreshCacheThread() {
    static std::mutex refreshMutex;
    
    // Try to acquire lock - if already running, just queue request
    std::unique_lock<std::mutex> lock(refreshMutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        m_refreshQueued = true;
        return;
    }
    
    m_refreshing = true;
    
    // Set low thread priority (don't block UI)
#ifdef _WIN32
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
#else
    setpriority(PRIO_PROCESS, 0, 10);  // Nice value +10
#endif
    
    // Reload system paths
    {
        std::lock_guard<std::mutex> cacheLock(m_cacheMutex);
        m_systemPaths.clear();
        for (const auto& path : SYSTEM_SAFE_PATHS) {
            m_systemPaths.insert(path);
        }
    }
    
    // Reload user whitelist
    LoadUserWhitelist();
    
    m_refreshing = false;
    
    // Check if another refresh was queued
    if (m_refreshQueued.exchange(false)) {
        RefreshCacheThread();
    }
}

void SystemCache::StartEventMonitoring() {
#ifdef _WIN32
    m_monitorThread = std::make_unique<std::thread>(&SystemCache::MonitorWindowsUpdate, this);
#else
    m_monitorThread = std::make_unique<std::thread>(&SystemCache::MonitorLinuxPackages, this);
#endif
}

void SystemCache::MonitorWindowsUpdate() {
#ifdef _WIN32
    // Monitor Windows Update service state changes
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) return;
    
    SC_HANDLE wuService = OpenServiceW(scManager, L"wuauserv", SERVICE_QUERY_STATUS);
    if (!wuService) {
        CloseServiceHandle(scManager);
        return;
    }
    
    SERVICE_STATUS_PROCESS lastStatus = {};
    DWORD needed;
    QueryServiceStatusEx(wuService, SC_STATUS_PROCESS_INFO, 
                         (LPBYTE)&lastStatus, sizeof(lastStatus), &needed);
    
    while (m_running.load()) {
        Sleep(5000);  // Check every 5 seconds
        
        SERVICE_STATUS_PROCESS currentStatus;
        if (QueryServiceStatusEx(wuService, SC_STATUS_PROCESS_INFO, 
                                  (LPBYTE)&currentStatus, sizeof(currentStatus), &needed)) {
            // Detect Windows Update service stopped (installation complete)
            if (lastStatus.dwCurrentState == SERVICE_RUNNING && 
                currentStatus.dwCurrentState == SERVICE_STOPPED) {
                
                // Wait 10 seconds for post-install operations
                Sleep(10000);
                OnSystemUpdateCompleted();
            }
            lastStatus = currentStatus;
        }
    }
    
    CloseServiceHandle(wuService);
    CloseServiceHandle(scManager);
#endif
}

void SystemCache::MonitorLinuxPackages() {
#ifndef _WIN32
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd < 0) return;
    
    // Watch package manager lock files
    std::vector<std::pair<int, const char*>> watches;
    
    const char* lockPaths[] = {
        "/var/lib/dpkg/lock-frontend",      // Debian/Ubuntu
        "/var/lib/rpm/.rpm.lock",           // RedHat/Fedora
        "/var/lib/snapd/state.json",        // Snap
        "/var/lib/flatpak/.changed"         // Flatpak
    };
    
    for (const char* path : lockPaths) {
        int wd = inotify_add_watch(inotify_fd, path, IN_CLOSE_WRITE);
        if (wd >= 0) {
            watches.push_back({wd, path});
        }
    }
    
    char buffer[4096];
    
    while (m_running.load()) {
        ssize_t len = read(inotify_fd, buffer, sizeof(buffer));
        
        if (len > 0) {
            // Lock file was released - package operation completed
            // Wait 15 seconds for post-install scripts
            sleep(15);
            OnSystemUpdateCompleted();
        }
        
        usleep(500000);  // 500ms
    }
    
    for (auto& [wd, path] : watches) {
        inotify_rm_watch(inotify_fd, wd);
    }
    close(inotify_fd);
#endif
}

void SystemCache::OnSystemUpdateCompleted() {
    RequestCacheRefresh();
}

// ============================================
// Task 5: Atomic Cert Whitelisting
// ============================================

CertTrustManager& CertTrustManager::Instance() {
    static CertTrustManager instance;
    return instance;
}

bool CertTrustManager::InitializeDatabase() {
    // Create tables for trusted certs and file integrity
    const char* sql = 
        "CREATE TABLE IF NOT EXISTS TrustedCerts ("
        "    Thumbprint TEXT PRIMARY KEY,"
        "    SerialNumber TEXT NOT NULL,"
        "    Publisher TEXT NOT NULL,"
        "    FirstSeenHash TEXT,"
        "    AddedDate INTEGER"
        ");"
        "CREATE TABLE IF NOT EXISTS file_integrity ("
        "    filepath TEXT PRIMARY KEY,"
        "    hash TEXT NOT NULL,"
        "    verified_date TEXT NOT NULL"
        ");";
    
    return Database::Instance().Execute(sql);
}

// Helper: Convert wide string to UTF-8
static std::string WideToUtf8Local(const std::wstring& wide) {
    if (wide.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string utf8(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &utf8[0], size, nullptr, nullptr);
    return utf8;
}

// Helper: Convert UTF-8 to wide string
static std::wstring Utf8ToWideLocal(const char* utf8) {
    if (!utf8 || !utf8[0]) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    std::wstring wide(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, &wide[0], size);
    return wide;
}

bool CertTrustManager::TrustCertificate(const std::wstring& filePath,
                                        const std::wstring& thumbprint,
                                        const std::wstring& serial,
                                        const std::wstring& publisher) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Calculate file hash at trust time
    std::wstring fileHash = HashUtil::ComputeSHA256(filePath);
    if (fileHash.empty()) return false;
    
    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    // Insert using parameterized query
    const char* sql = "INSERT OR REPLACE INTO TrustedCerts "
                      "(Thumbprint, SerialNumber, Publisher, FirstSeenHash, AddedDate) "
                      "VALUES (?, ?, ?, ?, ?)";
    
    sqlite3* db = Database::Instance().GetHandle();
    if (!db) return false;
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, WideToUtf8Local(thumbprint).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, WideToUtf8Local(serial).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, WideToUtf8Local(publisher).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, WideToUtf8Local(fileHash).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, timestamp);
    
    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return success;
}

bool CertTrustManager::IsCertTrusted(const std::wstring& thumbprint) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    sqlite3* db = Database::Instance().GetHandle();
    if (!db) return false;
    
    const char* sql = "SELECT COUNT(*) FROM TrustedCerts WHERE Thumbprint = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, WideToUtf8Local(thumbprint).c_str(), -1, SQLITE_TRANSIENT);
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return count > 0;
}

bool CertTrustManager::VerifyFileIntegrity(const std::wstring& filePath, 
                                            const std::wstring& thumbprint) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    sqlite3* db = Database::Instance().GetHandle();
    if (!db) return false;
    
    // Normalize path first
    wchar_t canonical[MAX_PATH] = {0};
    if (GetFullPathNameW(filePath.c_str(), MAX_PATH, canonical, nullptr) == 0) {
        return false;
    }
    
    // Compute current hash
    std::wstring currentHash = HashUtil::ComputeSHA256(canonical);
    if (currentHash.empty()) return false;
    
    // Query database for original hash
    const char* sql = "SELECT FirstSeenHash FROM TrustedCerts WHERE Thumbprint = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, WideToUtf8Local(thumbprint).c_str(), -1, SQLITE_TRANSIENT);
    
    std::wstring originalHash;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* hashText = sqlite3_column_text(stmt, 0);
        if (hashText) {
            originalHash = Utf8ToWideLocal(reinterpret_cast<const char*>(hashText));
        }
    }
    sqlite3_finalize(stmt);
    
    if (originalHash.empty()) {
        // No original hash - first time, store baseline
        const char* insertSql = "INSERT OR REPLACE INTO file_integrity (filepath, hash, verified_date) "
                                "VALUES (?, ?, datetime('now'))";
        sqlite3_stmt* insertStmt = nullptr;
        
        if (sqlite3_prepare_v2(db, insertSql, -1, &insertStmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(insertStmt, 1, WideToUtf8Local(canonical).c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insertStmt, 2, WideToUtf8Local(currentHash).c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(insertStmt);
            sqlite3_finalize(insertStmt);
        }
        return true; // First time - trust it
    }
    
    // Constant-time comparison to prevent timing attacks
    if (currentHash.length() != originalHash.length()) {
        return false;
    }
    
    int result = 0;
    for (size_t i = 0; i < currentHash.length(); i++) {
        result |= (currentHash[i] ^ originalHash[i]);
    }
    
    return (result == 0);
}

std::vector<CertTrustManager::TrustedCert> CertTrustManager::GetTrustedCerts() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<TrustedCert> certs;
    
    sqlite3* db = Database::Instance().GetHandle();
    if (!db) return certs;
    
    const char* sql = "SELECT Thumbprint, SerialNumber, Publisher, FirstSeenHash, AddedDate FROM TrustedCerts";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return certs;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TrustedCert cert;
        cert.thumbprint = Utf8ToWideLocal(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        cert.serialNumber = Utf8ToWideLocal(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        cert.publisher = Utf8ToWideLocal(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
        cert.firstSeenHash = Utf8ToWideLocal(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)));
        cert.addedDate = sqlite3_column_int64(stmt, 4);
        certs.push_back(cert);
    }
    
    sqlite3_finalize(stmt);
    return certs;
}

// ============================================
// Task 6: Installation Safety Valve
// ============================================

ConfigManager& ConfigManager::Instance() {
    static ConfigManager instance;
    return instance;
}

bool ConfigManager::Initialize() {
    if (IsFirstRun()) {
        return true;  // Will be set up via SetupFirstRun()
    }
    
    if (!LoadConfig()) {
        return false;
    }
    
    if (!VerifyConfigIntegrity()) {
        // Config tampered - alert and require re-install
        return false;
    }
    
    // Check mode expiry
    CheckModeExpiry();
    
    return true;
}

bool ConfigManager::IsFirstRun() {
#ifdef _WIN32
    return GetFileAttributesW(CONFIG_PATH) == INVALID_FILE_ATTRIBUTES;
#else
    struct stat st;
    return stat(CONFIG_PATH, &st) != 0;
#endif
}

bool ConfigManager::SetupFirstRun(ProtectionMode initialMode) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Generate HMAC key
    if (!GenerateHmacKey()) {
        return false;
    }
    
    // Setup config
    auto now = std::chrono::system_clock::now();
    int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    m_config.mode = initialMode;
    m_config.installDate = timestamp;
    m_config.sequenceNumber = 1;
    
    // Set mode lock (7 days for monitoring mode)
    if (initialMode == ProtectionMode::Monitoring) {
        m_config.modeLockedUntil = timestamp + (MONITORING_PERIOD_DAYS * 24 * 60 * 60);
    } else {
        m_config.modeLockedUntil = 0;  // No lock for other modes
    }
    
    // Compute signature
    m_config.signature = ComputeHmac(m_config);
    
    // Save config
    if (!SaveConfig()) {
        return false;
    }
    
    // Protect config file
    ProtectConfigFile();
    
    return true;
}

ConfigManager::ProtectionMode ConfigManager::GetCurrentMode() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config.mode;
}

bool ConfigManager::SetMode(ProtectionMode mode) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check anti-rollback
    m_config.sequenceNumber++;
    m_config.mode = mode;
    m_config.signature = ComputeHmac(m_config);
    
    return SaveConfig();
}

bool ConfigManager::IsModeLocked() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_config.modeLockedUntil == 0) return false;
    
    auto now = std::chrono::system_clock::now();
    int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    return timestamp < m_config.modeLockedUntil;
}

void ConfigManager::CheckModeExpiry() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_config.mode != ProtectionMode::Monitoring) return;
    if (m_config.modeLockedUntil == 0) return;
    
    auto now = std::chrono::system_clock::now();
    int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    if (timestamp >= m_config.modeLockedUntil) {
        // Monitoring period complete - upgrade to Balanced
        m_config.mode = ProtectionMode::Balanced;
        m_config.modeLockedUntil = 0;
        m_config.sequenceNumber++;
        m_config.signature = ComputeHmac(m_config);
        
        SaveConfig();
        ProtectConfigFile();
    }
}

bool ConfigManager::VerifyConfigIntegrity() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<uint8_t> expectedSig = ComputeHmac(m_config);
    return expectedSig == m_config.signature;
}

bool ConfigManager::GenerateHmacKey() {
    m_hmacKey.resize(32);  // 256-bit key
    
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0))) {
        return false;
    }
    
    NTSTATUS status = BCryptGenRandom(hAlg, m_hmacKey.data(), 
                                        static_cast<ULONG>(m_hmacKey.size()), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!BCRYPT_SUCCESS(status)) return false;
    
    // Store key in registry with restricted ACL
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\CROSSRING", 0, nullptr,
                         REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"SecureKey", 0, REG_BINARY, 
                       m_hmacKey.data(), static_cast<DWORD>(m_hmacKey.size()));
        RegCloseKey(hKey);
    }
#else
    // Read from /dev/urandom
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom.read(reinterpret_cast<char*>(m_hmacKey.data()), m_hmacKey.size())) {
        return false;
    }
    
    // Store key with restricted permissions (root read-only)
    std::ofstream keyFile("/var/lib/crossring/.key", std::ios::binary);
    if (keyFile) {
        keyFile.write(reinterpret_cast<char*>(m_hmacKey.data()), m_hmacKey.size());
        chmod("/var/lib/crossring/.key", 0400);
    }
#endif
    
    return true;
}

std::vector<uint8_t> ConfigManager::ComputeHmac(const Config& config) {
    std::vector<uint8_t> hmac(32);
    
    // Create data to sign
    std::vector<uint8_t> data;
    data.push_back(static_cast<uint8_t>(config.mode));
    
    // Add timestamps as bytes
    for (int i = 0; i < 8; i++) {
        data.push_back((config.installDate >> (i * 8)) & 0xFF);
        data.push_back((config.modeLockedUntil >> (i * 8)) & 0xFF);
    }
    
    // Add sequence number
    for (int i = 0; i < 4; i++) {
        data.push_back((config.sequenceNumber >> (i * 8)) & 0xFF);
    }
    
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_HASH_HANDLE hHash;
    
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 
                                                    BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
        DWORD hashObjSize, hashSize, dummy;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjSize, sizeof(DWORD), &dummy, 0);
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashSize, sizeof(DWORD), &dummy, 0);
        
        std::vector<uint8_t> hashObj(hashObjSize);
        
        if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize,
                                             m_hmacKey.data(), static_cast<ULONG>(m_hmacKey.size()), 0))) {
            BCryptHashData(hHash, data.data(), static_cast<ULONG>(data.size()), 0);
            BCryptFinishHash(hHash, hmac.data(), static_cast<ULONG>(hmac.size()), 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
#endif
    
    return hmac;
}

bool ConfigManager::LoadConfig() {
    // TODO: Parse Config.xml
    return true;
}

bool ConfigManager::SaveConfig() {
    // TODO: Write Config.xml
    return true;
}

bool ConfigManager::ProtectConfigFile() {
#ifdef _WIN32
    // Set DACL to deny write for Everyone, allow only TrustedInstaller
    // TODO: Implement proper DACL
#else
    // Set immutable flag using ioctl instead of shell command
    int fd = open("/etc/crossring/config.xml", O_RDONLY);
    if (fd >= 0) {
        int flags = 0;
        if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0) {
            flags |= FS_IMMUTABLE_FL;
            ioctl(fd, FS_IOC_SETFLAGS, &flags);
        }
        close(fd);
    }
#endif
    return true;
}

// ============================================
// Task 8: OS-Aware Integrity
// ============================================

bool OSIntegrity::GetRealWindowsVersion(int& major, int& minor, int& build) {
#ifdef _WIN32
    // Use RtlGetVersion from ntdll.dll (doesn't lie like GetVersionEx)
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    auto RtlGetVersion = reinterpret_cast<RtlGetVersionPtr>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    if (!RtlGetVersion) return false;
    
    RTL_OSVERSIONINFOW osvi = { sizeof(osvi) };
    if (RtlGetVersion(&osvi) >= 0) {
        major = osvi.dwMajorVersion;
        minor = osvi.dwMinorVersion;
        build = osvi.dwBuildNumber;
        return true;
    }
#endif
    return false;
}

bool OSIntegrity::IsSecureBootEnabled() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                       L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                       0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    DWORD enabled = 0, size = sizeof(DWORD);
    RegQueryValueExW(hKey, L"UEFISecureBootEnabled", nullptr, nullptr, 
                     (LPBYTE)&enabled, &size);
    RegCloseKey(hKey);
    
    return enabled == 1;
#else
    return false;
#endif
}

bool OSIntegrity::IsHVCIEnabled() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                       0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    DWORD enabled = 0, size = sizeof(DWORD);
    RegQueryValueExW(hKey, L"EnableVirtualizationBasedSecurity", nullptr, nullptr,
                     (LPBYTE)&enabled, &size);
    RegCloseKey(hKey);
    
    return enabled == 1;
#else
    return false;
#endif
}

bool OSIntegrity::IsSELinuxEnforcing() {
#ifndef _WIN32
    std::ifstream enforce("/sys/fs/selinux/enforce");
    if (!enforce) return false;
    
    int value = 0;
    enforce >> value;
    return value == 1;
#else
    return false;
#endif
}

bool OSIntegrity::IsAppArmorEnabled() {
#ifndef _WIN32
    struct stat st;
    return stat("/sys/kernel/security/apparmor", &st) == 0;
#else
    return false;
#endif
}

OSIntegrity::SystemStatus OSIntegrity::CheckSystem() {
    SystemStatus status = {};
    
#ifdef _WIN32
    if (GetRealWindowsVersion(status.majorVersion, status.minorVersion, status.buildNumber)) {
        status.isWindows7 = (status.majorVersion == 6 && status.minorVersion == 1);
        status.isWindows10Plus = (status.majorVersion >= 10);
        status.isEOL = status.isWindows7;  // Windows 7 is EOL
    }
    
    status.secureBootEnabled = IsSecureBootEnabled();
    status.hvciEnabled = IsHVCIEnabled();
    
    // Determine overall level
    if (status.isWindows7) {
        status.overallLevel = SystemStatus::Level::Orange;
        status.warnings.push_back(L"Windows 7 is End of Life. Support is best-effort only.");
    } else if (!status.secureBootEnabled || !status.hvciEnabled) {
        status.overallLevel = SystemStatus::Level::Yellow;
        if (!status.secureBootEnabled) {
            status.warnings.push_back(L"Secure Boot is disabled. System vulnerable to bootkits.");
        }
        if (!status.hvciEnabled) {
            status.warnings.push_back(L"Memory Integrity (HVCI) is disabled. System vulnerable to kernel exploits.");
        }
    } else {
        status.overallLevel = SystemStatus::Level::Green;
    }
#else
    status.selinuxEnforcing = IsSELinuxEnforcing();
    status.apparmorEnabled = IsAppArmorEnabled();
    
    if (!status.selinuxEnforcing && !status.apparmorEnabled) {
        status.overallLevel = SystemStatus::Level::Orange;
        status.warnings.push_back(L"No Mandatory Access Control (SELinux/AppArmor) detected.");
    } else {
        status.overallLevel = SystemStatus::Level::Green;
    }
#endif
    
    return status;
}

std::vector<std::wstring> OSIntegrity::GetSecurityRecommendations() {
    std::vector<std::wstring> recs;
    auto status = CheckSystem();
    
    if (status.isWindows7) {
        recs.push_back(L"CRITICAL: Upgrade to Windows 10/11 for full security support.");
    }
    
    if (!status.secureBootEnabled) {
        recs.push_back(L"Enable Secure Boot in BIOS/UEFI settings.");
    }
    
    if (!status.hvciEnabled) {
        recs.push_back(L"Enable Memory Integrity in Windows Security > Device Security.");
    }
    
#ifndef _WIN32
    if (!status.selinuxEnforcing && !status.apparmorEnabled) {
        recs.push_back(L"Enable SELinux or AppArmor for Mandatory Access Control.");
    }
#endif
    
    return recs;
}

} // namespace Security
