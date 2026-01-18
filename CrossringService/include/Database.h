#pragma once
#include "Common.h"
#include "sqlite3.h"

class Database {
public:
    static Database& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // Process events
    uint64_t InsertProcessEvent(const ProcessEvent& event);
    bool UpdateProcessDecision(uint64_t eventId, Decision decision, const std::wstring& reason);
    std::vector<ProcessEvent> GetRecentProcessEvents(int limit = 100);
    std::optional<ProcessEvent> GetProcessEventById(uint64_t id);
    
    // Memory anomalies
    uint64_t InsertMemoryAnomaly(const MemoryAnomaly& anomaly);
    std::vector<MemoryAnomaly> GetRecentAnomalies(int limit = 100);
    
    // Network events
    uint64_t InsertNetworkEvent(const NetworkEvent& event);
    std::vector<NetworkEvent> GetRecentNetworkEvents(int limit = 100);
    
    // Whitelist
    uint64_t AddWhitelistEntry(const WhitelistEntry& entry);
    bool RemoveWhitelistEntry(uint64_t id);
    std::vector<WhitelistEntry> GetAllWhitelistEntries();
    bool IsWhitelisted(const std::wstring& hash, const std::wstring& signer, const std::wstring& path);
    
    // Maintenance
    void PruneOldEvents(int daysToKeep = 90);
    
    // Direct access for advanced operations
    sqlite3* GetHandle() { return m_db; }
    bool Execute(const char* sql);
    
private:
    Database() = default;
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    
    bool CreateTables();
    std::string WideToUtf8(const std::wstring& wide);
    std::wstring Utf8ToWide(const std::string& utf8);
    
    sqlite3* m_db = nullptr;
    std::mutex m_mutex;
};
