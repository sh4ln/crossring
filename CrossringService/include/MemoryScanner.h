#pragma once
#include "Common.h"

class MemoryScanner {
public:
    static MemoryScanner& Instance();
    
    using AnomalyCallback = std::function<void(const MemoryAnomaly&)>;
    
    bool Start(AnomalyCallback callback);
    void Stop();
    bool IsRunning() const { return m_running.load(); }
    
    // Manual scan
    std::vector<MemoryAnomaly> ScanProcess(DWORD pid);
    std::vector<MemoryAnomaly> ScanAllProcesses();
    
private:
    MemoryScanner() = default;
    ~MemoryScanner();
    MemoryScanner(const MemoryScanner&) = delete;
    MemoryScanner& operator=(const MemoryScanner&) = delete;
    
    void ScannerThread();
    
    // Detection methods
    bool IsUnbackedExecutable(HANDLE hProcess, const MEMORY_BASIC_INFORMATION& mbi);
    bool HasSuspiciousProtection(const MEMORY_BASIC_INFORMATION& mbi);
    std::wstring QueryMappedFileName(HANDLE hProcess, LPVOID address);
    
    AnomalyCallback m_callback;
    std::atomic<bool> m_running{false};
    std::unique_ptr<std::thread> m_scannerThread;
    
    // Scan interval in milliseconds
    static constexpr DWORD SCAN_INTERVAL_MS = 30000; // 30 seconds
};
