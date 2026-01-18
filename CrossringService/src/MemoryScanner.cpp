// CROSSRING - Memory Scanner Implementation
#include "MemoryScanner.h"
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")
MemoryScanner::~MemoryScanner() { Stop(); }

MemoryScanner& MemoryScanner::Instance() {
    static MemoryScanner instance;
    return instance;
}

bool MemoryScanner::Start(AnomalyCallback callback) {
    if (m_running.load()) return true;
    m_callback = callback;
    m_running = true;
    m_scannerThread = std::make_unique<std::thread>(&MemoryScanner::ScannerThread, this);
    return true;
}

void MemoryScanner::Stop() {
    m_running = false;
    if (m_scannerThread && m_scannerThread->joinable()) m_scannerThread->join();
}

void MemoryScanner::ScannerThread() {
    while (m_running.load()) {
        auto anomalies = ScanAllProcesses();
        for (const auto& a : anomalies) {
            if (m_callback) m_callback(a);
        }
        for (DWORD i = 0; i < SCAN_INTERVAL_MS / 1000 && m_running.load(); ++i) {
            Sleep(1000);
        }
    }
}

std::vector<MemoryAnomaly> MemoryScanner::ScanAllProcesses() {
    std::vector<MemoryAnomaly> results;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return results;
    
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            auto anomalies = ScanProcess(pe.th32ProcessID);
            for (auto& a : anomalies) {
                a.processName = pe.szExeFile;
                results.push_back(a);
            }
        } while (Process32NextW(snapshot, &pe) && m_running.load());
    }
    CloseHandle(snapshot);
    return results;
}

std::vector<MemoryAnomaly> MemoryScanner::ScanProcess(DWORD pid) {
    std::vector<MemoryAnomaly> results;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return results;
    
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = nullptr;
    
    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (HasSuspiciousProtection(mbi) && IsUnbackedExecutable(hProcess, mbi)) {
            MemoryAnomaly a;
            a.timestamp = GetCurrentTimestamp();
            a.pid = pid;
            a.regionAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            a.regionSize = mbi.RegionSize;
            a.anomalyType = L"unbacked_executable";
            
            if (mbi.Protect & PAGE_EXECUTE_READWRITE)
                a.protection = L"RWX";
            else if (mbi.Protect & PAGE_EXECUTE_READ)
                a.protection = L"RX";
            else
                a.protection = L"X";
            
            results.push_back(a);
        }
        addr = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
    return results;
}

bool MemoryScanner::HasSuspiciousProtection(const MEMORY_BASIC_INFORMATION& mbi) {
    if (mbi.State != MEM_COMMIT) return false;
    DWORD exec = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & exec) != 0;
}

bool MemoryScanner::IsUnbackedExecutable(HANDLE hProcess, const MEMORY_BASIC_INFORMATION& mbi) {
    if (mbi.Type == MEM_IMAGE) return false; // Backed by file
    if (mbi.Type == MEM_MAPPED) {
        std::wstring mappedFile = QueryMappedFileName(hProcess, mbi.BaseAddress);
        if (!mappedFile.empty()) return false;
    }
    return true; // Private executable memory = suspicious
}

std::wstring MemoryScanner::QueryMappedFileName(HANDLE hProcess, LPVOID address) {
    wchar_t filename[MAX_PATH] = {};
    if (GetMappedFileNameW(hProcess, address, filename, MAX_PATH)) {
        return filename;
    }
    return L"";
}
