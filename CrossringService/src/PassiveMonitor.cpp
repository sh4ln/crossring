// CROSSRING Passive Monitoring Implementation - Part 1
// Tasks 9, 10, 11: Kernel Detection, Injection Detection, Update Whitelisting

#include "PassiveMonitor.h"
#include "HashUtil.h"
#include <fstream>
#include <algorithm>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

namespace PassiveMonitor {

// ============================================
// Task 9: Kernel-Mode Threat Detection
// ============================================

KernelIntegrity& KernelIntegrity::Instance() {
    static KernelIntegrity instance;
    return instance;
}

bool KernelIntegrity::IsDriverSigningEnforced() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"SYSTEM\\CurrentControlSet\\Control\\CI\\CodeIntegrity",
                       0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return true;  // Assume enabled if can't check
    }
    
    DWORD value = 0, size = sizeof(DWORD);
    LONG result = RegQueryValueExW(hKey, L"IntegrityCheckResult", nullptr, nullptr,
                                    (LPBYTE)&value, &size);
    RegCloseKey(hKey);
    
    // Value 0 = all checks passed
    return (result == ERROR_SUCCESS) ? (value == 0) : true;
#else
    return true;
#endif
}

std::set<DWORD> KernelIntegrity::GetToolhelpPids() {
    std::set<DWORD> pids;
    
#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return pids;
    
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            pids.insert(pe.th32ProcessID);
        } while (Process32NextW(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
#endif
    
    return pids;
}

std::set<DWORD> KernelIntegrity::GetNtQueryPids() {
    std::set<DWORD> pids;
    
#ifdef _WIN32
    typedef NTSTATUS(NTAPI* NtQuerySystemInformationPtr)(
        SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return pids;
    
    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationPtr>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!NtQuerySystemInformation) return pids;
    
    // Allocate buffer for process info
    ULONG bufferSize = 1024 * 1024;  // 1 MB
    std::vector<uint8_t> buffer(bufferSize);
    ULONG returnLength;
    
    NTSTATUS status = NtQuerySystemInformation(
        SystemProcessInformation, buffer.data(), bufferSize, &returnLength);
    
    if (status != 0) return pids;  // STATUS_SUCCESS = 0
    
    // Parse process entries
    auto* process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buffer.data());
    
    while (true) {
        pids.insert(reinterpret_cast<DWORD>(process->UniqueProcessId));
        
        if (process->NextEntryOffset == 0) break;
        process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
            reinterpret_cast<uint8_t*>(process) + process->NextEntryOffset);
    }
#endif
    
    return pids;
}

std::vector<DWORD> KernelIntegrity::FindHiddenProcesses() {
    std::vector<DWORD> hidden;
    
    // Optimized: Only compare PIDs from two different enumeration methods
    // NOT the full 0-65535 range
    std::set<DWORD> toolhelpPids = GetToolhelpPids();
    std::set<DWORD> ntQueryPids = GetNtQueryPids();
    
    // PIDs in NtQuery but not in Toolhelp could be hidden
    for (DWORD pid : ntQueryPids) {
        if (toolhelpPids.find(pid) == toolhelpPids.end()) {
            // Verify with OpenProcess before flagging
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProcess) {
                hidden.push_back(pid);
                CloseHandle(hProcess);
            }
        }
    }
    
    // PIDs accessible by OpenProcess but not in either list (rare rootkit behavior)
    // Only check gaps in the enumerated ranges, not 0-65535
    DWORD maxPid = 0;
    for (DWORD pid : ntQueryPids) {
        if (pid > maxPid) maxPid = pid;
    }
    
    // Check gaps only between enumerated PIDs (much faster)
    std::set<DWORD> allKnown;
    allKnown.insert(toolhelpPids.begin(), toolhelpPids.end());
    allKnown.insert(ntQueryPids.begin(), ntQueryPids.end());
    
    DWORD prevPid = 0;
    for (DWORD pid : allKnown) {
        // Check gaps > 100 PIDs (unusual, might indicate hiding)
        if (pid - prevPid > 100) {
            for (DWORD checkPid = prevPid + 4; checkPid < pid; checkPid += 4) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, checkPid);
                if (hProcess) {
                    // Process exists but not enumerated - suspicious
                    hidden.push_back(checkPid);
                    CloseHandle(hProcess);
                }
            }
        }
        prevPid = pid;
    }
    
    return hidden;
}

bool KernelIntegrity::CheckSyscallIntegrity() {
#ifdef _WIN32
    // Compare NtCreateFile address in memory vs on-disk ntdll.dll
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return true;
    
    // Get memory address
    auto* memoryAddr = reinterpret_cast<uint8_t*>(
        GetProcAddress(ntdll, "NtCreateFile"));
    if (!memoryAddr) return true;
    
    // First bytes of NtCreateFile should start with "mov r10, rcx; mov eax, <syscall#>"
    // 0x4C 0x8B 0xD1, 0xB8, ...
    // If first byte is 0xE9 (jmp) or 0x68 (push), it's likely hooked
    
    if (memoryAddr[0] == 0xE9 || memoryAddr[0] == 0x68) {
        return false;  // Syscall appears to be hooked
    }
    
    // Expected pattern for Windows 10+: mov r10, rcx
    if (memoryAddr[0] != 0x4C || memoryAddr[1] != 0x8B || memoryAddr[2] != 0xD1) {
        // Could be different Windows version or hooked
        // Log for analysis but don't block
        return false;
    }
#endif
    
    return true;
}

KernelIntegrity::ThreatIndicators KernelIntegrity::Scan() {
    ThreatIndicators indicators = {};
    
    indicators.driverSigningDisabled = !IsDriverSigningEnforced();
    indicators.hiddenPids = FindHiddenProcesses();
    indicators.syscallHooked = !CheckSyscallIntegrity();
    
    return indicators;
}

// ============================================
// Task 10: Code Injection Detection
// ============================================

const std::vector<std::wstring> InjectionDetector::DEFAULT_WHITELIST = {
    // Visual Studio & debuggers
    L"devenv.exe", L"vshost.exe", L"msvsmon.exe", L"vsjitdebugger.exe",
    L"windbg.exe", L"x64dbg.exe", L"ollydbg.exe", L"ida.exe", L"ida64.exe",
    
    // Game overlays
    L"discord.exe", L"discordptb.exe", L"discordcanary.exe",
    L"steamwebhelper.exe", L"steamoverlay.exe", L"steam.exe",
    L"nvidia share.exe", L"nvspcaps64.exe", L"geforce experience.exe",
    L"origin.exe", L"epicgameslauncher.exe", L"radeonsoftware.exe",
    L"obs64.exe", L"obs32.exe",
    
    // Game anti-cheat (they use injection legitimately)
    L"easyanticheat.exe", L"easyanticheat_eos.exe",
    L"battleye.exe", L"beclient.exe", L"beservice.exe",
    L"vanguard.exe", L"vgtray.exe",
    
    // Accessibility
    L"nvda.exe", L"nvda_service.exe", L"nvda_slave.exe",
    L"jfw.exe", L"narrator.exe", L"magnify.exe",
    L"zoomtext.exe", L"fusion.exe",
    
    // System tools
    L"taskmgr.exe", L"procexp.exe", L"procexp64.exe",
    L"perfmon.exe", L"resmon.exe",
    
    // IDEs & Development
    L"code.exe", L"rider64.exe", L"clion64.exe", L"pycharm64.exe",
    L"idea64.exe", L"webstorm64.exe", L"goland64.exe"
};

InjectionDetector& InjectionDetector::Instance() {
    static InjectionDetector instance;
    return instance;
}

bool InjectionDetector::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Load default whitelist
    for (const auto& proc : DEFAULT_WHITELIST) {
        m_whitelist.insert(proc);
    }
    
    // TODO: Start ETW monitoring for injection APIs
    m_running = true;
    
    return true;
}

void InjectionDetector::Shutdown() {
    m_running = false;
    if (m_thread && m_thread->joinable()) {
        m_thread->join();
    }
}

bool InjectionDetector::IsWhitelisted(const std::wstring& processName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Normalize to lowercase
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    return m_whitelist.find(lower) != m_whitelist.end();
}

void InjectionDetector::AddToWhitelist(const std::wstring& processName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    m_whitelist.insert(lower);
    
    // TODO: Persist to config file
}

int InjectionDetector::CalculateRiskScore(const InjectionEvent& event) {
    int score = 0;
    
    // Base64 in command line
    // +20 points
    
    // Remote thread into explorer.exe
    std::wstring lowerTarget = event.targetProcess;
    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);
    
    if (lowerTarget.find(L"explorer.exe") != std::wstring::npos) {
        score += 40;
    }
    
    // Injection from Temp folder
    std::wstring lowerSource = event.sourceProcess;
    std::transform(lowerSource.begin(), lowerSource.end(), lowerSource.begin(), ::towlower);
    
    if (lowerSource.find(L"\\temp\\") != std::wstring::npos ||
        lowerSource.find(L"\\tmp\\") != std::wstring::npos) {
        score += 30;
    }
    
    // CreateRemoteThread is higher risk than SetWindowsHookEx
    if (event.apiUsed == L"CreateRemoteThread" || 
        event.apiUsed == L"NtCreateThreadEx") {
        score += 20;
    }
    else if (event.apiUsed == L"WriteProcessMemory") {
        score += 15;
    }
    else if (event.apiUsed == L"QueueUserAPC") {
        score += 25;
    }
    
    return score;
}

std::vector<InjectionDetector::RwxRegion> InjectionDetector::ScanForRwxMemory() {
    std::vector<RwxRegion> regions;
    
#ifdef _WIN32
    // JIT compiler processes to whitelist
    std::vector<std::wstring> jitProcesses = {
        L"chrome.exe", L"msedge.exe", L"firefox.exe", L"opera.exe", L"brave.exe",
        L"java.exe", L"javaw.exe", L"node.exe", L"electron.exe",
        L"dotnet.exe", L"powershell.exe", L"pwsh.exe",
        L"python.exe", L"pythonw.exe", L"ruby.exe",
        L"code.exe"  // VS Code
    };
    
    // Enumerate all processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return regions;
    
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            std::wstring procName = pe.szExeFile;
            std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);
            
            // Check if JIT process
            bool isJit = false;
            for (const auto& jit : jitProcesses) {
                if (procName == jit) {
                    isJit = true;
                    break;
                }
            }
            
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                                          FALSE, pe.th32ProcessID);
            if (hProcess) {
                MEMORY_BASIC_INFORMATION mbi;
                uintptr_t addr = 0;
                
                while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
                    // Check for RWX pages
                    if (mbi.State == MEM_COMMIT &&
                        (mbi.Protect == PAGE_EXECUTE_READWRITE || 
                         mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
                        
                        RwxRegion region;
                        region.pid = pe.th32ProcessID;
                        region.process = pe.szExeFile;
                        region.address = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                        region.size = mbi.RegionSize;
                        region.isJit = isJit;
                        
                        regions.push_back(region);
                    }
                    
                    addr += mbi.RegionSize;
                    if (addr < reinterpret_cast<uintptr_t>(mbi.BaseAddress)) break;  // Overflow
                }
                
                CloseHandle(hProcess);
            }
        } while (Process32NextW(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
#endif
    
    return regions;
}

// ============================================
// Task 11: Update Process Whitelisting
// ============================================

const std::vector<std::wstring> UpdateProtection::WINDOWS_UPDATE_PATHS = {
    L"C:\\Windows\\System32\\wuauclt.exe",
    L"C:\\Windows\\System32\\TrustedInstaller.exe",
    L"C:\\Windows\\System32\\svchost.exe",  // Hosts Windows Update services
    L"C:\\Windows\\WinSxS\\",               // All WinSxS paths
    L"C:\\Windows\\servicing\\",
    L"C:\\Windows\\SoftwareDistribution\\",
    L"C:\\Windows\\System32\\msiexec.exe",
    L"C:\\Windows\\System32\\dism.exe",
    L"C:\\Windows\\System32\\pkgmgr.exe"
};

const std::vector<std::wstring> UpdateProtection::TRUSTED_INSTALLER_VENDORS = {
    L"Microsoft Corporation",
    L"Microsoft Windows",
    L"Adobe Inc.",
    L"Adobe Systems Incorporated",
    L"Google LLC",
    L"Google Inc.",
    L"Mozilla Corporation",
    L"Apple Inc.",
    L"Oracle Corporation",
    L"NVIDIA Corporation",
    L"Intel Corporation",
    L"Advanced Micro Devices",
    L"Valve Corp.",
    L"Valve Corporation"
};

UpdateProtection& UpdateProtection::Instance() {
    static UpdateProtection instance;
    return instance;
}

UpdateProtection::UpdateProtection() {
    // Open update log file
    std::wstring logPath = L"C:\\ProgramData\\CROSSRING\\update_log.txt";
    m_updateLog.open(logPath, std::ios::app);
}

bool UpdateProtection::IsSystemUpdate(const std::wstring& path, const std::wstring& signer) {
    std::wstring lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    
    // Check permanent whitelist paths
    for (const auto& wuPath : WINDOWS_UPDATE_PATHS) {
        std::wstring lowerWu = wuPath;
        std::transform(lowerWu.begin(), lowerWu.end(), lowerWu.begin(), ::towlower);
        
        if (lowerPath.find(lowerWu) == 0) {
            LogUpdateActivity(path, L"Auto-allowed: Windows Update path");
            return true;
        }
    }
    
    // Check signer
    std::wstring lowerSigner = signer;
    std::transform(lowerSigner.begin(), lowerSigner.end(), lowerSigner.begin(), ::towlower);
    
    if (lowerSigner.find(L"microsoft") != std::wstring::npos &&
        (lowerSigner.find(L"windows") != std::wstring::npos ||
         lowerPath.find(L"\\windows\\") != std::wstring::npos)) {
        LogUpdateActivity(path, L"Auto-allowed: Microsoft Windows signed");
        return true;
    }
    
    return false;
}

bool UpdateProtection::IsKnownInstaller(const std::wstring& path, const std::wstring& signer) {
    // Check if file name suggests installer
    std::wstring lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    
    bool hasInstallerName = 
        lowerPath.find(L"setup") != std::wstring::npos ||
        lowerPath.find(L"install") != std::wstring::npos ||
        lowerPath.find(L"update") != std::wstring::npos ||
        lowerPath.find(L"patch") != std::wstring::npos;
    
    if (!hasInstallerName) return false;
    
    // Check if signed by known vendor
    std::wstring lowerSigner = signer;
    std::transform(lowerSigner.begin(), lowerSigner.end(), lowerSigner.begin(), ::towlower);
    
    for (const auto& vendor : TRUSTED_INSTALLER_VENDORS) {
        std::wstring lowerVendor = vendor;
        std::transform(lowerVendor.begin(), lowerVendor.end(), lowerVendor.begin(), ::towlower);
        
        if (lowerSigner.find(lowerVendor) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

bool UpdateProtection::IsUnattendedUpdateActive() {
#ifdef _WIN32
    // Check if Windows Update service is actively running
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) return false;
    
    SC_HANDLE wuService = OpenServiceW(scManager, L"wuauserv", SERVICE_QUERY_STATUS);
    if (!wuService) {
        CloseServiceHandle(scManager);
        return false;
    }
    
    SERVICE_STATUS_PROCESS status;
    DWORD needed;
    BOOL result = QueryServiceStatusEx(wuService, SC_STATUS_PROCESS_INFO,
                                        (LPBYTE)&status, sizeof(status), &needed);
    
    CloseServiceHandle(wuService);
    CloseServiceHandle(scManager);
    
    return result && status.dwCurrentState == SERVICE_RUNNING;
#else
    // Check for package manager lock files
    struct stat st;
    if (stat("/var/lib/dpkg/lock-frontend", &st) == 0) {
        return true;  // Debian/Ubuntu update in progress
    }
    if (stat("/var/lib/rpm/.rpm.lock", &st) == 0) {
        return true;  // RedHat update in progress
    }
    return false;
#endif
}

void UpdateProtection::LogUpdateActivity(const std::wstring& process, const std::wstring& action) {
    std::lock_guard<std::mutex> lock(m_logMutex);
    
    if (!m_updateLog.is_open()) return;
    
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    char timeStr[64];
    std::tm tm;
    localtime_s(&tm, &time);
    std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm);
    
    m_updateLog << timeStr << " | ";
    
    // Convert to narrow string for log
    std::string narrowProcess(process.begin(), process.end());
    std::string narrowAction(action.begin(), action.end());
    
    m_updateLog << narrowProcess << " | " << narrowAction << std::endl;
    m_updateLog.flush();
}

} // namespace PassiveMonitor
