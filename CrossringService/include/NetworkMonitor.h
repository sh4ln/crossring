#pragma once
#include "Common.h"
#include <iphlpapi.h>
#include <tcpmib.h>

#pragma comment(lib, "iphlpapi.lib")

class NetworkMonitor {
public:
    static NetworkMonitor& Instance();
    
    bool Start();
    void Stop();
    bool IsRunning() const { return m_running.load(); }
    
    using NetworkCallback = std::function<void(const NetworkEvent&)>;
    void SetCallback(NetworkCallback callback) { m_callback = callback; }
    
    // Get current connections
    std::vector<NetworkEvent> GetTcpConnections();
    std::vector<NetworkEvent> GetUdpEndpoints();
    
    // Phantom connection detection
    struct PhantomConnection {
        std::wstring remoteAddr;
        uint16_t remotePort;
        std::wstring timestamp;
        bool hasVisibleProcess;
    };
    
    std::vector<PhantomConnection> DetectPhantomConnections();
    
    // DNS monitoring
    struct DnsQuery {
        std::wstring domain;
        DWORD pid;
        std::wstring timestamp;
    };
    
    // Suspicious connection detection
    bool IsSuspiciousPort(uint16_t port);
    bool IsSuspiciousAddress(const std::wstring& addr);
    
private:
    NetworkMonitor() = default;
    ~NetworkMonitor();
    
    void MonitorThread();
    std::wstring IpToString(DWORD ip);
    std::wstring GetProcessNameByPid(DWORD pid);
    
    NetworkCallback m_callback;
    std::atomic<bool> m_running{false};
    std::unique_ptr<std::thread> m_monitorThread;
    
    // Previous connections for change detection
    std::vector<NetworkEvent> m_previousConnections;
    std::mutex m_mutex;
    
    static constexpr DWORD SCAN_INTERVAL_MS = 5000; // 5 seconds
    
    // Suspicious ports (common C2 ports)
    static const std::vector<uint16_t> SUSPICIOUS_PORTS;
};
