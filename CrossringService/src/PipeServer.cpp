// CROSSRING - Named Pipe Server Implementation
#include "PipeServer.h"
#include <sddl.h>

PipeServer::PipeServer() : m_running(false), m_clientConnected(false), m_clientPipe(INVALID_HANDLE_VALUE) {
    GenerateHmacKey();
}

PipeServer::~PipeServer() { Stop(); }

PipeServer& PipeServer::Instance() {
    static PipeServer instance;
    return instance;
}

bool PipeServer::GenerateHmacKey() {
    m_hmacKey.resize(32); // 256-bit key
    
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0) != 0) {
        return false;
    }
    
    NTSTATUS status = BCryptGenRandom(hAlg, m_hmacKey.data(), 32, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (status != 0) {
        return false;
    }
    
    // Store key in protected registry for GUI to read
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\CROSSRING\\IPC", 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"Secret", 0, REG_BINARY, m_hmacKey.data(), 32);
        RegCloseKey(hKey);
    }
    
    return true;
}

std::string PipeServer::ComputeHmac(const std::string& data) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        return "";
    }
    
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, m_hmacKey.data(), 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
    
    BCryptHashData(hHash, (PUCHAR)data.c_str(), static_cast<ULONG>(data.length()), 0);
    
    UCHAR hash[32];
    BCryptFinishHash(hHash, hash, 32, 0);
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    // Convert to hex string
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return ss.str();
}

bool PipeServer::VerifyMessageHmac(const json& msg) {
    if (!msg.contains("hmac") || !msg["hmac"].is_string()) {
        return false;
    }
    
    std::string providedHmac = msg["hmac"];
    
    // Create copy without HMAC field
    json msgCopy = msg;
    msgCopy.erase("hmac");
    
    std::string payload = msgCopy.dump();
    std::string computedHmac = ComputeHmac(payload);
    
    // Constant-time comparison
    if (providedHmac.length() != computedHmac.length()) {
        return false;
    }
    
    int result = 0;
    for (size_t i = 0; i < providedHmac.length(); i++) {
        result |= (providedHmac[i] ^ computedHmac[i]);
    }
    
    return (result == 0);
}

bool PipeServer::Start(MessageCallback callback) {
    if (m_running.load()) return true;
    m_callback = callback;
    m_running = true;
    m_listenerThread = std::make_unique<std::thread>(&PipeServer::ListenerThread, this);
    return true;
}

void PipeServer::Stop() {
    m_running = false;
    m_clientConnected = false;
    std::lock_guard<std::mutex> lock(m_clientMutex);
    if (m_clientPipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(m_clientPipe);
        CloseHandle(m_clientPipe);
        m_clientPipe = INVALID_HANDLE_VALUE;
    }
    if (m_listenerThread && m_listenerThread->joinable()) m_listenerThread->join();
}

bool PipeServer::CreateSecurityDescriptor(PSECURITY_DESCRIPTOR* ppSD) {
    // Restrict pipe access to SYSTEM and Administrators only
    // GUI must run elevated to connect
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, ppSD, nullptr) != FALSE;
}

void PipeServer::ListenerThread() {
    while (m_running.load()) {
        PSECURITY_DESCRIPTOR pSD = nullptr;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, FALSE };
        if (CreateSecurityDescriptor(&pSD)) sa.lpSecurityDescriptor = pSD;

        HANDLE pipe = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1,
            PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, &sa);
        if (pSD) LocalFree(pSD);
        if (pipe == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }

        if (ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            std::lock_guard<std::mutex> lock(m_clientMutex);
            m_clientPipe = pipe;
            m_clientConnected = true;
        }
        ClientThread(pipe);
        {
            std::lock_guard<std::mutex> lock(m_clientMutex);
            m_clientPipe = INVALID_HANDLE_VALUE;
            m_clientConnected = false;
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}

void PipeServer::ClientThread(HANDLE pipe) {
    char buffer[PIPE_BUFFER_SIZE];
    while (m_running.load() && m_clientConnected.load()) {
        DWORD bytesRead = 0;
        if (!ReadFile(pipe, buffer, sizeof(buffer), &bytesRead, nullptr) || bytesRead == 0) break;
        if (bytesRead > 4) {
            uint32_t msgLen = *reinterpret_cast<uint32_t*>(buffer);
            
            // FIX #3: Message size limit to prevent DoS
            const uint32_t MAX_MESSAGE_SIZE = 1048576; // 1MB limit
            if (msgLen > MAX_MESSAGE_SIZE) {
                // Disconnect malicious client sending huge message
                break;
            }
            
            if (msgLen <= bytesRead - 4) {
                try {
                    json msg = json::parse(std::string(buffer + 4, msgLen));
                    
                    // FIX #4: Validate message structure
                    if (!msg.contains("type") || !msg["type"].is_string()) {
                        // Malformed message, skip
                        continue;
                    }
                    
                    // CRITICAL #3: Verify HMAC authentication
                    if (!VerifyMessageHmac(msg)) {
                        // Log unauthorized message attempt and reject
                        continue;
                    }
                    
                    std::string msgType = msg["type"];
                    if (msgType != "decision" && msgType != "query" && msgType != "config") {
                        // Unknown message type, skip
                        continue;
                    }
                    
                    if (m_callback) m_callback(msg);
                } catch (...) {}
            }
        }
    }
}

bool PipeServer::SendMessage(const json& message) {
    std::lock_guard<std::mutex> lock(m_clientMutex);
    if (!m_clientConnected.load() || m_clientPipe == INVALID_HANDLE_VALUE) return false;
    std::string jsonStr = message.dump();
    uint32_t len = static_cast<uint32_t>(jsonStr.size());
    std::vector<char> buf(4 + len);
    memcpy(buf.data(), &len, 4);
    memcpy(buf.data() + 4, jsonStr.c_str(), len);
    DWORD written;
    return WriteFile(m_clientPipe, buf.data(), static_cast<DWORD>(buf.size()), &written, nullptr);
}

static std::string WtoU(const std::wstring& w) {
    if (w.empty()) return "";
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string u(sz - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &u[0], sz, nullptr, nullptr);
    return u;
}

void PipeServer::NotifyProcessBlocked(const ProcessEvent& e) {
    json msg = {{"type", "process_blocked"}, {"event_id", e.id}, {"pid", e.pid},
        {"image_path", WtoU(e.imagePath)}, {"hash", WtoU(e.hashSha256)},
        {"signed", e.isSigned}, {"signer", WtoU(e.signer)}};
    SendMessage(msg);
}

void PipeServer::NotifyAnomaly(const MemoryAnomaly& a) {
    json msg = {{"type", "anomaly"}, {"pid", a.pid}, {"process_name", WtoU(a.processName)},
        {"anomaly_type", WtoU(a.anomalyType)}, {"region_size", a.regionSize}};
    SendMessage(msg);
}

void PipeServer::NotifyNetworkEvent(const NetworkEvent& e) {
    json msg = {{"type", "network"}, {"pid", e.pid}, {"remote_addr", WtoU(e.remoteAddr)},
        {"remote_port", e.remotePort}};
    SendMessage(msg);
}
