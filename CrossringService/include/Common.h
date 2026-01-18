#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <optional>

// Service configuration
constexpr const wchar_t* SERVICE_NAME = L"CrossringService";
constexpr const wchar_t* SERVICE_DISPLAY_NAME = L"CROSSRING Security Service";
constexpr const wchar_t* CROSSRING_SERVICE_DESC = L"Owner-gated endpoint security monitoring and enforcement";

// Named pipe for IPC
constexpr const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\CrossringPipe";
constexpr DWORD PIPE_BUFFER_SIZE = 65536;

// Database path
constexpr const wchar_t* DATA_DIR = L"C:\\ProgramData\\CROSSRING";
constexpr const wchar_t* DATABASE_PATH = L"C:\\ProgramData\\CROSSRING\\database.db";
constexpr const wchar_t* CONFIG_PATH = L"C:\\ProgramData\\CROSSRING\\config.xml";
constexpr const wchar_t* LOG_DIR = L"C:\\ProgramData\\CROSSRING\\logs";

// Event types
enum class EventType {
    ProcessCreated,
    ProcessTerminated,
    ScriptExecution,
    NetworkConnection,
    MemoryAnomaly,
    PersistenceChange,
    UsbDevice,
    TamperAttempt
};

// Decision types
enum class Decision {
    Pending,
    AllowOnce,
    AllowSession,
    AllowPermanent,
    Deny
};

// Process event structure
struct ProcessEvent {
    uint64_t id = 0;
    std::wstring timestamp;
    EventType eventType = EventType::ProcessCreated;
    DWORD pid = 0;
    DWORD parentPid = 0;
    std::wstring imagePath;
    std::wstring commandLine;
    std::wstring hashSha256;
    bool isSigned = false;
    std::wstring signer;
    Decision decision = Decision::Pending;
    std::wstring decisionReason;
};

// Memory anomaly structure
struct MemoryAnomaly {
    uint64_t id = 0;
    std::wstring timestamp;
    DWORD pid = 0;
    std::wstring processName;
    uint64_t regionAddress = 0;
    size_t regionSize = 0;
    std::wstring protection;
    std::wstring anomalyType;
};

// Network event structure
struct NetworkEvent {
    uint64_t id = 0;
    std::wstring timestamp;
    DWORD pid = 0;
    std::wstring localAddr;
    uint16_t localPort = 0;
    std::wstring remoteAddr;
    uint16_t remotePort = 0;
    std::wstring protocol;
};

// Whitelist entry
struct WhitelistEntry {
    uint64_t id = 0;
    std::wstring entryType;  // "hash", "signer", "path"
    std::wstring value;
    std::wstring addedTimestamp;
    std::wstring notes;
};

// Utility functions
inline std::wstring GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time);
    std::wstringstream ss;
    ss << std::put_time(&tm, L"%Y-%m-%d %H:%M:%S");
    return ss.str();
}

inline std::wstring EventTypeToString(EventType type) {
    switch (type) {
        case EventType::ProcessCreated: return L"ProcessCreated";
        case EventType::ProcessTerminated: return L"ProcessTerminated";
        case EventType::ScriptExecution: return L"ScriptExecution";
        case EventType::NetworkConnection: return L"NetworkConnection";
        case EventType::MemoryAnomaly: return L"MemoryAnomaly";
        case EventType::PersistenceChange: return L"PersistenceChange";
        case EventType::UsbDevice: return L"UsbDevice";
        case EventType::TamperAttempt: return L"TamperAttempt";
        default: return L"Unknown";
    }
}

inline std::wstring DecisionToString(Decision d) {
    switch (d) {
        case Decision::Pending: return L"Pending";
        case Decision::AllowOnce: return L"AllowOnce";
        case Decision::AllowSession: return L"AllowSession";
        case Decision::AllowPermanent: return L"AllowPermanent";
        case Decision::Deny: return L"Deny";
        default: return L"Unknown";
    }
}
