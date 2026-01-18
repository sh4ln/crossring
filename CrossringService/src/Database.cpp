// CROSSRING - SQLite Database Implementation
#include "Database.h"
#include <filesystem>

// Helper to safely get text from SQLite (MSVC doesn't support GNU ?: extension)
inline const char* SafeText(const unsigned char* text) {
    return text ? reinterpret_cast<const char*>(text) : "";
}

Database::~Database() {
    Shutdown();
}

Database& Database::Instance() {
    static Database instance;
    return instance;
}

bool Database::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Ensure directory exists
    std::filesystem::create_directories(DATA_DIR);
    
    std::string dbPath = WideToUtf8(DATABASE_PATH);
    int rc = sqlite3_open(dbPath.c_str(), &m_db);
    if (rc != SQLITE_OK) {
        return false;
    }
    
    // Enable WAL mode for better performance
    sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
    
    return CreateTables();
}

void Database::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
}

bool Database::CreateTables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS process_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            pid INTEGER NOT NULL,
            parent_pid INTEGER,
            image_path TEXT,
            command_line TEXT,
            hash_sha256 TEXT,
            is_signed INTEGER DEFAULT 0,
            signer TEXT,
            decision TEXT DEFAULT 'Pending',
            decision_reason TEXT
        );
        
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pid INTEGER,
            local_addr TEXT,
            local_port INTEGER,
            remote_addr TEXT,
            remote_port INTEGER,
            protocol TEXT
        );
        
        CREATE TABLE IF NOT EXISTS memory_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pid INTEGER NOT NULL,
            process_name TEXT,
            region_address TEXT,
            region_size INTEGER,
            protection TEXT,
            anomaly_type TEXT
        );
        
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_type TEXT NOT NULL,
            value TEXT NOT NULL,
            added_timestamp TEXT,
            notes TEXT,
            UNIQUE(entry_type, value)
        );
        
        CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            process_event_id INTEGER,
            decision TEXT NOT NULL,
            scope TEXT,
            FOREIGN KEY (process_event_id) REFERENCES process_events(id)
        );
        
        CREATE INDEX IF NOT EXISTS idx_process_timestamp ON process_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_process_hash ON process_events(hash_sha256);
        CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_anomaly_timestamp ON memory_anomalies(timestamp);
    )";
    
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

uint64_t Database::InsertProcessEvent(const ProcessEvent& event) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return 0;
    
    const char* sql = R"(
        INSERT INTO process_events 
        (timestamp, event_type, pid, parent_pid, image_path, command_line, 
         hash_sha256, is_signed, signer, decision, decision_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, WideToUtf8(event.timestamp).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, WideToUtf8(EventTypeToString(event.eventType)).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, event.pid);
    sqlite3_bind_int(stmt, 4, event.parentPid);
    sqlite3_bind_text(stmt, 5, WideToUtf8(event.imagePath).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, WideToUtf8(event.commandLine).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, WideToUtf8(event.hashSha256).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 8, event.isSigned ? 1 : 0);
    sqlite3_bind_text(stmt, 9, WideToUtf8(event.signer).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, WideToUtf8(DecisionToString(event.decision)).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, WideToUtf8(event.decisionReason).c_str(), -1, SQLITE_TRANSIENT);
    
    uint64_t id = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        id = static_cast<uint64_t>(sqlite3_last_insert_rowid(m_db));
    }
    sqlite3_finalize(stmt);
    return id;
}

bool Database::UpdateProcessDecision(uint64_t eventId, Decision decision, const std::wstring& reason) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return false;
    
    const char* sql = "UPDATE process_events SET decision = ?, decision_reason = ? WHERE id = ?";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, WideToUtf8(DecisionToString(decision)).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, WideToUtf8(reason).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, eventId);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

std::vector<ProcessEvent> Database::GetRecentProcessEvents(int limit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ProcessEvent> events;
    if (!m_db) return events;
    
    const char* sql = "SELECT * FROM process_events ORDER BY id DESC LIMIT ?";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return events;
    }
    sqlite3_bind_int(stmt, 1, limit);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ProcessEvent event;
        event.id = sqlite3_column_int64(stmt, 0);
        event.timestamp = Utf8ToWide(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        // ... populate other fields
        event.pid = sqlite3_column_int(stmt, 3);
        event.parentPid = sqlite3_column_int(stmt, 4);
        event.imagePath = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 5)));
        event.commandLine = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 6)));
        event.hashSha256 = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 7)));
        event.isSigned = sqlite3_column_int(stmt, 8) != 0;
        event.signer = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 9)));
        events.push_back(event);
    }
    sqlite3_finalize(stmt);
    return events;
}

std::optional<ProcessEvent> Database::GetProcessEventById(uint64_t id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return std::nullopt;
    
    const char* sql = "SELECT * FROM process_events WHERE id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    sqlite3_bind_int64(stmt, 1, id);
    
    std::optional<ProcessEvent> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        ProcessEvent event;
        event.id = sqlite3_column_int64(stmt, 0);
        event.pid = sqlite3_column_int(stmt, 3);
        event.imagePath = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 5)));
        result = event;
    }
    sqlite3_finalize(stmt);
    return result;
}

uint64_t Database::InsertMemoryAnomaly(const MemoryAnomaly& anomaly) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return 0;
    
    const char* sql = R"(
        INSERT INTO memory_anomalies 
        (timestamp, pid, process_name, region_address, region_size, protection, anomaly_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    std::wstringstream addrStr;
    addrStr << std::hex << anomaly.regionAddress;
    
    sqlite3_bind_text(stmt, 1, WideToUtf8(anomaly.timestamp).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, anomaly.pid);
    sqlite3_bind_text(stmt, 3, WideToUtf8(anomaly.processName).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, WideToUtf8(addrStr.str()).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, anomaly.regionSize);
    sqlite3_bind_text(stmt, 6, WideToUtf8(anomaly.protection).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, WideToUtf8(anomaly.anomalyType).c_str(), -1, SQLITE_TRANSIENT);
    
    uint64_t id = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        id = static_cast<uint64_t>(sqlite3_last_insert_rowid(m_db));
    }
    sqlite3_finalize(stmt);
    return id;
}

std::vector<MemoryAnomaly> Database::GetRecentAnomalies(int limit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<MemoryAnomaly> anomalies;
    if (!m_db) return anomalies;
    
    const char* sql = "SELECT * FROM memory_anomalies ORDER BY id DESC LIMIT ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return anomalies;
    }
    sqlite3_bind_int(stmt, 1, limit);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        MemoryAnomaly a;
        a.id = sqlite3_column_int64(stmt, 0);
        a.timestamp = Utf8ToWide(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        a.pid = sqlite3_column_int(stmt, 2);
        a.processName = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 3)));
        a.regionSize = sqlite3_column_int64(stmt, 5);
        a.anomalyType = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 7)));
        anomalies.push_back(a);
    }
    sqlite3_finalize(stmt);
    return anomalies;
}

uint64_t Database::InsertNetworkEvent(const NetworkEvent& event) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return 0;
    
    const char* sql = R"(
        INSERT INTO network_events 
        (timestamp, pid, local_addr, local_port, remote_addr, remote_port, protocol)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, WideToUtf8(event.timestamp).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, event.pid);
    sqlite3_bind_text(stmt, 3, WideToUtf8(event.localAddr).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, event.localPort);
    sqlite3_bind_text(stmt, 5, WideToUtf8(event.remoteAddr).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, event.remotePort);
    sqlite3_bind_text(stmt, 7, WideToUtf8(event.protocol).c_str(), -1, SQLITE_TRANSIENT);
    
    uint64_t id = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        id = static_cast<uint64_t>(sqlite3_last_insert_rowid(m_db));
    }
    sqlite3_finalize(stmt);
    return id;
}

std::vector<NetworkEvent> Database::GetRecentNetworkEvents(int limit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<NetworkEvent> events;
    if (!m_db) return events;
    
    const char* sql = "SELECT * FROM network_events ORDER BY id DESC LIMIT ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return events;
    }
    sqlite3_bind_int(stmt, 1, limit);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        NetworkEvent e;
        e.id = sqlite3_column_int64(stmt, 0);
        e.timestamp = Utf8ToWide(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        e.pid = sqlite3_column_int(stmt, 2);
        e.localAddr = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 3)));
        e.localPort = static_cast<uint16_t>(sqlite3_column_int(stmt, 4));
        e.remoteAddr = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 5)));
        e.remotePort = static_cast<uint16_t>(sqlite3_column_int(stmt, 6));
        e.protocol = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 7)));
        events.push_back(e);
    }
    sqlite3_finalize(stmt);
    return events;
}

uint64_t Database::AddWhitelistEntry(const WhitelistEntry& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return 0;
    
    const char* sql = R"(
        INSERT OR REPLACE INTO whitelist (entry_type, value, added_timestamp, notes)
        VALUES (?, ?, ?, ?)
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, WideToUtf8(entry.entryType).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, WideToUtf8(entry.value).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, WideToUtf8(entry.addedTimestamp).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, WideToUtf8(entry.notes).c_str(), -1, SQLITE_TRANSIENT);
    
    uint64_t id = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        id = static_cast<uint64_t>(sqlite3_last_insert_rowid(m_db));
    }
    sqlite3_finalize(stmt);
    return id;
}

bool Database::RemoveWhitelistEntry(uint64_t id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return false;
    
    const char* sql = "DELETE FROM whitelist WHERE id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_int64(stmt, 1, id);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

std::vector<WhitelistEntry> Database::GetAllWhitelistEntries() {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<WhitelistEntry> entries;
    if (!m_db) return entries;
    
    const char* sql = "SELECT * FROM whitelist ORDER BY id";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return entries;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WhitelistEntry e;
        e.id = sqlite3_column_int64(stmt, 0);
        e.entryType = Utf8ToWide(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        e.value = Utf8ToWide(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
        e.addedTimestamp = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 3)));
        e.notes = Utf8ToWide(SafeText(sqlite3_column_text(stmt, 4)));
        entries.push_back(e);
    }
    sqlite3_finalize(stmt);
    return entries;
}

bool Database::IsWhitelisted(const std::wstring& hash, const std::wstring& signer, const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return false;
    
    const char* sql = R"(
        SELECT 1 FROM whitelist WHERE 
        (entry_type = 'hash' AND value = ?) OR
        (entry_type = 'signer' AND value = ?) OR
        (entry_type = 'path' AND value = ?)
        LIMIT 1
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, WideToUtf8(hash).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, WideToUtf8(signer).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, WideToUtf8(path).c_str(), -1, SQLITE_TRANSIENT);
    
    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return found;
}

void Database::PruneOldEvents(int daysToKeep) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return;
    
    // FIX: Use parameterized queries to prevent SQL injection
    const char* sql = "DELETE FROM process_events WHERE timestamp < datetime('now', ? || ' days')";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, -daysToKeep);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    sql = "DELETE FROM network_events WHERE timestamp < datetime('now', ? || ' days')";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, -daysToKeep);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    sql = "DELETE FROM memory_anomalies WHERE timestamp < datetime('now', ? || ' days')";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, -daysToKeep);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    sqlite3_exec(m_db, "VACUUM", nullptr, nullptr, nullptr);
}

bool Database::Execute(const char* sql) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return false;
    
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) sqlite3_free(errMsg);
        return false;
    }
    return true;
}

std::string Database::WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string utf8(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &utf8[0], size, nullptr, nullptr);
    return utf8;
}

std::wstring Database::Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    std::wstring wide(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wide[0], size);
    return wide;
}
