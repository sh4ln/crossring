#pragma once
#include "Common.h"

class PersistenceMonitor {
public:
    static PersistenceMonitor& Instance();
    
    bool Start();
    void Stop();
    bool IsRunning() const { return m_running.load(); }
    
    struct PersistenceEntry {
        std::wstring type;       // "Registry", "StartupFolder", "ScheduledTask", "Service"
        std::wstring location;   // Key path, folder path, task name
        std::wstring value;      // Executable or command
        std::wstring timestamp;
        bool isNew;
    };
    
    using PersistenceCallback = std::function<void(const PersistenceEntry&)>;
    void SetCallback(PersistenceCallback callback) { m_callback = callback; }
    
    // Get current baseline
    std::vector<PersistenceEntry> GetCurrentPersistence();
    
    // Baseline management
    void TakeBaseline();
    std::vector<PersistenceEntry> DetectChanges();
    
private:
    PersistenceMonitor() = default;
    ~PersistenceMonitor();
    
    void MonitorThread();
    
    // Registry monitoring
    std::vector<PersistenceEntry> ScanRegistryRun();
    std::vector<PersistenceEntry> ScanRegistryRunOnce();
    std::vector<PersistenceEntry> ScanServices();
    
    // Folder monitoring
    std::vector<PersistenceEntry> ScanStartupFolders();
    
    // Scheduled task monitoring
    std::vector<PersistenceEntry> ScanScheduledTasks();
    
    PersistenceCallback m_callback;
    std::atomic<bool> m_running{false};
    std::unique_ptr<std::thread> m_monitorThread;
    
    std::vector<PersistenceEntry> m_baseline;
    std::mutex m_baselineMutex;
    
    static constexpr DWORD SCAN_INTERVAL_MS = 60000; // 1 minute
    
    // Registry paths to monitor
    static const std::vector<std::wstring> REGISTRY_RUN_KEYS;
};
