// CROSSRING - Network Monitor Implementation
#include "NetworkMonitor.h"
#include <unordered_set>
#include <tlhelp32.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

const std::vector<uint16_t> NetworkMonitor::SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 7777, 8888, 9999,  // Common RAT ports
    1234, 31337, 12345,                   // Classic backdoors
    6667, 6668, 6669,                     // IRC (C2)
    8080, 8443,                           // Alt HTTP/HTTPS
    443, 80,                              // Web (suspicious for unknown processes)
};

NetworkMonitor::~NetworkMonitor() { Stop(); }

NetworkMonitor& NetworkMonitor::Instance() {
    static NetworkMonitor instance;
    return instance;
}

bool NetworkMonitor::Start() {
    if (m_running.load()) return true;
    m_running = true;
    m_monitorThread = std::make_unique<std::thread>(&NetworkMonitor::MonitorThread, this);
    return true;
}

void NetworkMonitor::Stop() {
    m_running = false;
    if (m_monitorThread && m_monitorThread->joinable()) {
        m_monitorThread->join();
    }
}

void NetworkMonitor::MonitorThread() {
    while (m_running.load()) {
        auto connections = GetTcpConnections();
        
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Detect new connections
        for (const auto& conn : connections) {
            bool isNew = true;
            for (const auto& prev : m_previousConnections) {
                if (conn.pid == prev.pid && 
                    conn.remoteAddr == prev.remoteAddr && 
                    conn.remotePort == prev.remotePort) {
                    isNew = false;
                    break;
                }
            }
            if (isNew && m_callback) {
                m_callback(conn);
            }
        }
        
        m_previousConnections = connections;
        
        for (DWORD i = 0; i < SCAN_INTERVAL_MS / 1000 && m_running.load(); ++i) {
            Sleep(1000);
        }
    }
}

std::vector<NetworkEvent> NetworkMonitor::GetTcpConnections() {
    std::vector<NetworkEvent> events;
    
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    std::vector<BYTE> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            auto& row = table->table[i];
            
            // Only established connections
            if (row.dwState == MIB_TCP_STATE_ESTAB) {
                NetworkEvent event;
                event.timestamp = GetCurrentTimestamp();
                event.pid = row.dwOwningPid;
                event.localAddr = IpToString(row.dwLocalAddr);
                event.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                event.remoteAddr = IpToString(row.dwRemoteAddr);
                event.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
                event.protocol = L"TCP";
                events.push_back(event);
            }
        }
    }
    
    return events;
}

std::vector<NetworkEvent> NetworkMonitor::GetUdpEndpoints() {
    std::vector<NetworkEvent> events;
    
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    
    std::vector<BYTE> buffer(size);
    if (GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buffer.data());
        
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            auto& row = table->table[i];
            
            NetworkEvent event;
            event.timestamp = GetCurrentTimestamp();
            event.pid = row.dwOwningPid;
            event.localAddr = IpToString(row.dwLocalAddr);
            event.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
            event.protocol = L"UDP";
            events.push_back(event);
        }
    }
    
    return events;
}

std::vector<NetworkMonitor::PhantomConnection> NetworkMonitor::DetectPhantomConnections() {
    std::vector<PhantomConnection> phantoms;
    auto connections = GetTcpConnections();
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return phantoms;
    
    std::unordered_set<DWORD> visiblePids;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            visiblePids.insert(pe.th32ProcessID);
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    
    for (const auto& conn : connections) {
        if (visiblePids.find(conn.pid) == visiblePids.end()) {
            PhantomConnection phantom;
            phantom.remoteAddr = conn.remoteAddr;
            phantom.remotePort = conn.remotePort;
            phantom.timestamp = conn.timestamp;
            phantom.hasVisibleProcess = false;
            phantoms.push_back(phantom);
        }
    }
    
    return phantoms;
}

bool NetworkMonitor::IsSuspiciousPort(uint16_t port) {
    for (uint16_t p : SUSPICIOUS_PORTS) {
        if (port == p) return true;
    }
    return false;
}

bool NetworkMonitor::IsSuspiciousAddress(const std::wstring& addr) {
    // Private ranges are less suspicious
    if (addr.find(L"192.168.") == 0) return false;
    if (addr.find(L"10.") == 0) return false;
    if (addr.find(L"172.") == 0) return false; // Simplified
    if (addr == L"127.0.0.1") return false;
    if (addr == L"0.0.0.0") return false;
    
    // External addresses from unknown processes are suspicious
    return true;
}

std::wstring NetworkMonitor::IpToString(DWORD ip) {
    wchar_t str[16];
    swprintf_s(str, L"%u.%u.%u.%u",
        ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    return str;
}

std::wstring NetworkMonitor::GetProcessNameByPid(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return L"";
    
    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    QueryFullProcessImageNameW(hProcess, 0, path, &size);
    CloseHandle(hProcess);
    
    std::wstring pathStr = path;
    auto pos = pathStr.find_last_of(L"\\/");
    return pos != std::wstring::npos ? pathStr.substr(pos + 1) : pathStr;
}
