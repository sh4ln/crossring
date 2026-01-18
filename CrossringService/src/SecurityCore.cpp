// CROSSRING Security Core Implementation - Part 1
// Tasks 1, 2, 4, 7: Self-Immunity, Safe Mode, Privilege Detection, Smart Kill

#include "SecurityCore.h"
#include "HashUtil.h"
#include <fstream>
#include <random>

#ifdef _WIN32
#include <Windows.h>
#include <Shlwapi.h>
#include <shellapi.h>
#include <gdiplus.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "gdiplus.lib")
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include <limits.h>
#include <signal.h>
#endif

namespace Security {

// ============================================
// Task 1: Self-Immunity with Symlink Protection
// ============================================

SelfProtection& SelfProtection::Instance() {
    static SelfProtection instance;
    return instance;
}

std::wstring SelfProtection::ResolveRealPath(const std::wstring& path) {
#ifdef _WIN32
    // Use GetFinalPathNameByHandle for true canonical path
    HANDLE hFile = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return path;  // Return original if can't resolve
    }
    
    wchar_t canonicalPath[MAX_PATH * 2] = {};
    DWORD len = GetFinalPathNameByHandleW(hFile, canonicalPath, sizeof(canonicalPath) / sizeof(wchar_t), 
                                           FILE_NAME_NORMALIZED);
    CloseHandle(hFile);
    
    if (len == 0) return path;
    
    // Remove \\?\ prefix if present
    std::wstring result = canonicalPath;
    if (result.compare(0, 4, L"\\\\?\\") == 0) {
        result = result.substr(4);
    }
    
    // Normalize to lowercase for comparison
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
#else
    char resolved[PATH_MAX];
    std::string narrowPath(path.begin(), path.end());
    
    if (realpath(narrowPath.c_str(), resolved) == nullptr) {
        return path;
    }
    
    return std::wstring(resolved, resolved + strlen(resolved));
#endif
}

bool SelfProtection::Initialize(const std::wstring& installDir) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_installDir = installDir;
    m_protectedBinaries.clear();
    
    // Define protected binaries (ONLY specific files, NOT entire directory)
    std::vector<std::wstring> protectedNames = {
#ifdef _WIN32
        L"CrossringService.exe",
        L"CrossringUI.exe",
        L"crossring-updater.exe",
        L"crossring-agent.exe"
#else
        L"crossring-daemon",
        L"crossring-gui",
        L"crossring-updater"
#endif
    };
    
    for (const auto& name : protectedNames) {
        std::wstring fullPath = installDir + L"/" + name;
        
        // Only add if file exists
#ifdef _WIN32
        if (GetFileAttributesW(fullPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
#else
        struct stat st;
        std::string narrowPath(fullPath.begin(), fullPath.end());
        if (stat(narrowPath.c_str(), &st) == 0) {
#endif
            ProtectedBinary pb;
            pb.canonicalPath = ResolveRealPath(fullPath);
            pb.sha256Hash = HashUtil::ComputeSHA256(fullPath);
            m_protectedBinaries.push_back(pb);
        }
    }
    
    return !m_protectedBinaries.empty();
}

bool SelfProtection::IsProtectedBinary(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Resolve target's canonical path (handles symlinks/junctions)
    std::wstring targetCanonical = ResolveRealPath(path);
    
    for (const auto& pb : m_protectedBinaries) {
        if (targetCanonical == pb.canonicalPath) {
            // Additional integrity check - verify hash matches
            std::wstring currentHash = HashUtil::ComputeSHA256(path);
            if (currentHash == pb.sha256Hash) {
                return true;  // Legitimate CROSSRING binary
            }
            // Hash mismatch - file was replaced, DO NOT protect impostor
        }
    }
    
    return false;
}

bool SelfProtection::VerifyProtectedIntegrity() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (const auto& pb : m_protectedBinaries) {
        std::wstring currentHash = HashUtil::ComputeSHA256(pb.canonicalPath);
        if (currentHash != pb.sha256Hash) {
            return false;  // Integrity violation
        }
    }
    
    return true;
}

// ============================================
// Task 2: Safe Mode Challenge (Visual CAPTCHA)
// ============================================

SafeModeChallenge& SafeModeChallenge::Instance() {
    static SafeModeChallenge instance;
    return instance;
}

void SafeModeChallenge::StartMonitoring() {
    if (m_running.load()) return;
    
    m_running = true;
    m_thread = std::make_unique<std::thread>(&SafeModeChallenge::MonitorThread, this);
}

void SafeModeChallenge::StopMonitoring() {
    m_running = false;
    if (m_thread && m_thread->joinable()) {
        m_thread->join();
    }
}

void SafeModeChallenge::MonitorThread() {
    while (m_running.load()) {
#ifdef _WIN32
        DWORD attrs = GetFileAttributesW(SAFEMODE_FILE);
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            // Safemode file detected - trigger challenge
            DeleteFileW(SAFEMODE_FILE);  // Remove file immediately
            
            if (m_callback) {
                m_callback();
            }
        }
        Sleep(1000);  // Check every second
#else
        struct stat st;
        if (stat(SAFEMODE_FILE, &st) == 0) {
            unlink(SAFEMODE_FILE);  // Remove file immediately
            
            if (m_callback) {
                m_callback();
            }
        }
        sleep(1);
#endif
    }
}

SafeModeChallenge::Challenge SafeModeChallenge::GenerateChallenge() {
    Challenge challenge;
    
    // Generate random math problem
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(10, 50);
    
    challenge.operand1 = dis(gen);
    challenge.operand2 = dis(gen);
    challenge.correctAnswer = challenge.operand1 + challenge.operand2;
    challenge.expiry = std::chrono::steady_clock::now() + 
                       std::chrono::seconds(CHALLENGE_TIMEOUT_SECONDS);
    
    // Render as image (anti-OCR)
    challenge.captchaImage = RenderMathCaptcha(challenge.operand1, challenge.operand2);
    
    return challenge;
}

std::vector<uint8_t> SafeModeChallenge::RenderMathCaptcha(int a, int b) {
    std::vector<uint8_t> pngData;
    
#ifdef _WIN32
    // Use GDI+ to render text as image
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);
    
    // Create bitmap
    Gdiplus::Bitmap bitmap(200, 60, PixelFormat32bppARGB);
    Gdiplus::Graphics graphics(&bitmap);
    
    // Background with noise (anti-OCR)
    graphics.Clear(Gdiplus::Color(255, 240, 240, 245));
    
    // Add noise lines
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> colorDis(100, 200);
    std::uniform_int_distribution<> posDis(0, 60);
    
    Gdiplus::Pen noisePen(Gdiplus::Color(255, colorDis(gen), colorDis(gen), colorDis(gen)), 1);
    for (int i = 0; i < 5; i++) {
        graphics.DrawLine(&noisePen, 0, posDis(gen), 200, posDis(gen));
    }
    
    // Draw text with slight rotation
    wchar_t text[32];
    swprintf_s(text, L"%d + %d = ?", a, b);
    
    Gdiplus::Font font(L"Arial", 24, Gdiplus::FontStyleBold);
    Gdiplus::SolidBrush brush(Gdiplus::Color(255, 50, 50, 80));
    
    Gdiplus::Matrix matrix;
    matrix.RotateAt(-3.0f, Gdiplus::PointF(100, 30));
    graphics.SetTransform(&matrix);
    
    Gdiplus::StringFormat format;
    format.SetAlignment(Gdiplus::StringAlignmentCenter);
    format.SetLineAlignment(Gdiplus::StringAlignmentCenter);
    
    graphics.DrawString(text, -1, &font, Gdiplus::RectF(0, 0, 200, 60), &format, &brush);
    
    // Save to PNG in memory
    IStream* stream;
    CreateStreamOnHGlobal(nullptr, TRUE, &stream);
    
    CLSID pngClsid;
    CLSIDFromString(L"{557CF406-1A04-11D3-9A73-0000F81EF32E}", &pngClsid);
    bitmap.Save(stream, &pngClsid, nullptr);
    
    // Get data from stream
    STATSTG stats;
    stream->Stat(&stats, STATFLAG_NONAME);
    
    pngData.resize(static_cast<size_t>(stats.cbSize.QuadPart));
    LARGE_INTEGER zero = {};
    stream->Seek(zero, STREAM_SEEK_SET, nullptr);
    
    ULONG read;
    stream->Read(pngData.data(), static_cast<ULONG>(pngData.size()), &read);
    
    stream->Release();
    Gdiplus::GdiplusShutdown(gdiplusToken);
#endif
    
    return pngData;
}

bool SafeModeChallenge::ValidateChallenge(const Challenge& challenge, int userAnswer) {
    // Check timeout
    if (std::chrono::steady_clock::now() > challenge.expiry) {
        return false;  // Challenge expired
    }
    
    return userAnswer == challenge.correctAnswer;
}

// ============================================
// Task 4: Privilege Detection
// ============================================

PrivilegeChecker::PrivilegeLevel PrivilegeChecker::GetCurrentLevel() {
    Capabilities caps = GetCapabilities();
    
    if (caps.canTerminateProcesses && caps.canQuarantine && caps.canFilterNetwork) {
        return PrivilegeLevel::Full;
    } else if (caps.canTerminateProcesses || caps.canQuarantine) {
        return PrivilegeLevel::Limited;
    }
    
    return PrivilegeLevel::Minimal;
}

PrivilegeChecker::Capabilities PrivilegeChecker::GetCapabilities() {
    Capabilities caps = {};
    
#ifdef _WIN32
    caps.canTerminateProcesses = HasSeDebugPrivilege();
    caps.canQuarantine = HasSeDebugPrivilege();  // Need admin for file ops
    caps.canFilterNetwork = HasSeDebugPrivilege();  // Need admin for WFP
    
    // Check if running as admin
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            caps.canModifyRegistry = elevation.TokenIsElevated != 0;
        }
        CloseHandle(token);
    }
#else
    caps.canTerminateProcesses = (geteuid() == 0);
    caps.canQuarantine = (geteuid() == 0);
    caps.canFilterNetwork = HasCapSysAdmin();
    caps.canModifyRegistry = (geteuid() == 0);
    caps.canAccessKernel = HasCapSysAdmin();
#endif
    
    return caps;
}

bool PrivilegeChecker::HasSeDebugPrivilege() {
#ifdef _WIN32
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return false;
    }
    
    PRIVILEGE_SET privSet = {};
    privSet.PrivilegeCount = 1;
    privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privSet.Privilege[0].Luid = luid;
    privSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    BOOL hasPriv = FALSE;
    PrivilegeCheck(token, &privSet, &hasPriv);
    CloseHandle(token);
    
    return hasPriv != FALSE;
#else
    return false;
#endif
}

bool PrivilegeChecker::HasCapSysAdmin() {
#ifdef _WIN32
    return false;
#else
    cap_t caps = cap_get_proc();
    if (!caps) return false;
    
    cap_flag_value_t value;
    bool hasCap = (cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &value) == 0 && value == CAP_SET);
    
    cap_free(caps);
    return hasCap;
#endif
}

bool PrivilegeChecker::RestartElevated() {
#ifdef _WIN32
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = path;
    sei.nShow = SW_SHOWNORMAL;
    
    if (ShellExecuteExW(&sei)) {
        ExitProcess(0);
        return true;
    }
    return false;
#else
    // Linux: Use pkexec
    char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len > 0) {
        path[len] = '\0';
        execlp("pkexec", "pkexec", path, nullptr);
    }
    return false;
#endif
}

// ============================================
// Task 7: Smart Kill Loop
// ============================================

ProcessTerminator::TerminationResult ProcessTerminator::Terminate(
    DWORD pid, const TerminationOptions& options, ProgressCallback progressCb) {
    
    // Step 1: Graceful shutdown
    if (progressCb) progressCb(L"Requesting graceful shutdown...", 5);
    
    if (GracefulShutdown(pid)) {
        // Step 2: Wait with feedback
        for (int i = 0; i < 50; i++) {  // 5 seconds total
            if (!IsProcessRunning(pid)) {
                return TerminationResult::GracefulExit;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            if (options.showProgress && progressCb && i % 10 == 0) {
                progressCb(L"Waiting for process to close...", 5 - (i / 10));
            }
        }
    }
    
    // Step 3: Forced termination
    if (progressCb) progressCb(L"Forcing termination...", 0);
    
    if (ForcedTerminate(pid)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        if (!IsProcessRunning(pid)) {
            return TerminationResult::ForcedKill;
        }
    }
    
    // Step 4: Kernel-level fallback
    if (options.useKernelFallback) {
        if (progressCb) progressCb(L"Using kernel-level termination...", 0);
        
        if (KernelTerminate(pid)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            if (!IsProcessRunning(pid)) {
                return TerminationResult::KernelKill;
            }
        }
        
        // Process still running - possible rootkit
        return TerminationResult::PossibleRootkit;
    }
    
    return TerminationResult::Failed;
}

bool ProcessTerminator::GracefulShutdown(DWORD pid) {
#ifdef _WIN32
    // Post WM_CLOSE to all top-level windows owned by process
    struct EnumData {
        DWORD pid;
        bool success;
    } data = { pid, false };
    
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<EnumData*>(lParam);
        DWORD windowPid;
        GetWindowThreadProcessId(hwnd, &windowPid);
        
        if (windowPid == data->pid) {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            data->success = true;
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&data));
    
    return data.success;
#else
    return kill(pid, SIGTERM) == 0;
#endif
}

bool ProcessTerminator::ForcedTerminate(DWORD pid) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return false;
    
    BOOL result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    
    return result != FALSE;
#else
    return kill(pid, SIGKILL) == 0;
#endif
}

bool ProcessTerminator::KernelTerminate(DWORD pid) {
#ifdef _WIN32
    // Use undocumented ZwTerminateProcess from ntdll (bypasses hooks)
    typedef NTSTATUS(NTAPI* ZwTerminateProcessPtr)(HANDLE, NTSTATUS);
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    auto ZwTerminateProcess = reinterpret_cast<ZwTerminateProcessPtr>(
        GetProcAddress(ntdll, "ZwTerminateProcess"));
    if (!ZwTerminateProcess) return false;
    
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return false;
    
    NTSTATUS status = ZwTerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    
    return status >= 0;
#else
    // Try cgroup kill
    char cgroupPath[256];
    snprintf(cgroupPath, sizeof(cgroupPath), "/sys/fs/cgroup/pids/crossring/%d/cgroup.procs", pid);
    
    std::ofstream cgroupFile(cgroupPath);
    if (cgroupFile) {
        cgroupFile << pid;
        return true;
    }
    
    return false;
#endif
}

bool ProcessTerminator::IsProcessRunning(DWORD pid) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;
    
    DWORD exitCode;
    BOOL result = GetExitCodeProcess(hProcess, &exitCode);
    CloseHandle(hProcess);
    
    return result && exitCode == STILL_ACTIVE;
#else
    return kill(pid, 0) == 0;
#endif
}

} // namespace Security
