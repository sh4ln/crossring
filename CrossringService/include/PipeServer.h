#pragma once
#include "Common.h"
#include <nlohmann/json.hpp>
#include <bcrypt.h>
#include <sstream>
#include <iomanip>
#pragma comment(lib, "bcrypt.lib")

using json = nlohmann::json;

class PipeServer {
public:
    static PipeServer& Instance();
    
    using MessageCallback = std::function<void(const json&)>;
    
    bool Start(MessageCallback callback);
    void Stop();
    bool IsRunning() const { return m_running.load(); }
    
    // Send message to connected GUI
    bool SendMessage(const json& message);
    
    // Convenience methods
    void NotifyProcessBlocked(const ProcessEvent& event);
    void NotifyAnomaly(const MemoryAnomaly& anomaly);
    void NotifyNetworkEvent(const NetworkEvent& event);
    
private:
    PipeServer();
    ~PipeServer();
    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;
    
    void ListenerThread();
    void ClientThread(HANDLE pipe);
    bool CreateSecurityDescriptor(PSECURITY_DESCRIPTOR* ppSD);
    
    // HMAC authentication for IPC messages
    bool GenerateHmacKey();
    bool VerifyMessageHmac(const json& msg);
    std::string ComputeHmac(const std::string& data);
    
    MessageCallback m_callback;
    std::atomic<bool> m_running{false};
    std::unique_ptr<std::thread> m_listenerThread;
    
    HANDLE m_clientPipe = INVALID_HANDLE_VALUE;
    std::mutex m_clientMutex;
    std::atomic<bool> m_clientConnected{false};
    
    // HMAC key for message authentication
    std::vector<uint8_t> m_hmacKey;
};
