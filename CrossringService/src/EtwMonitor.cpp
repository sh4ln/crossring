// CROSSRING - ETW Process Monitor Implementation
#include "EtwMonitor.h"
#include <psapi.h>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// ETW event IDs for Microsoft-Windows-Kernel-Process
constexpr USHORT EVENT_ID_PROCESS_START = 1;
constexpr USHORT EVENT_ID_PROCESS_STOP = 2;

// Thread-local storage for callback
thread_local EtwMonitor* g_etwMonitor = nullptr;

EtwMonitor::~EtwMonitor() {
    Stop();
}

EtwMonitor& EtwMonitor::Instance() {
    static EtwMonitor instance;
    return instance;
}

bool EtwMonitor::Start(ProcessCallback callback) {
    if (m_running.load()) return true;
    
    m_callback = callback;
    m_running = true;
    
    if (!StartTraceSession()) {
        m_running = false;
        return false;
    }
    
    m_processThread = std::make_unique<std::thread>(&EtwMonitor::ProcessThread, this);
    return true;
}

void EtwMonitor::Stop() {
    if (!m_running.load()) return;
    
    m_running = false;
    StopTraceSession();
    
    if (m_processThread && m_processThread->joinable()) {
        m_processThread->join();
    }
}

bool EtwMonitor::StartTraceSession() {
    // Stop any existing session with same name
    StopTraceSession();
    
    // Calculate buffer size for session properties
    size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t);
    m_sessionProperties.resize(bufferSize);
    
    auto* props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(m_sessionProperties.data());
    ZeroMemory(props, bufferSize);
    
    props->Wnode.BufferSize = static_cast<ULONG>(bufferSize);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; // QPC clock resolution
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    
    wcscpy_s(reinterpret_cast<wchar_t*>(m_sessionProperties.data() + sizeof(EVENT_TRACE_PROPERTIES)),
             wcslen(SESSION_NAME) + 1, SESSION_NAME);
    
    ULONG status = StartTraceW(&m_sessionHandle, SESSION_NAME, props);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        return false;
    }
    
    // Enable the kernel process provider
    status = EnableTraceEx2(
        m_sessionHandle,
        &KERNEL_PROCESS_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0, 0, 0,
        nullptr
    );
    
    if (status != ERROR_SUCCESS) {
        ControlTraceW(m_sessionHandle, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        return false;
    }
    
    return true;
}

void EtwMonitor::StopTraceSession() {
    if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(m_traceHandle);
        m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    
    if (!m_sessionProperties.empty()) {
        auto* props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(m_sessionProperties.data());
        ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    }
    
    m_sessionHandle = 0;
}

void EtwMonitor::ProcessThread() {
    g_etwMonitor = this;
    
    EVENT_TRACE_LOGFILEW logFile = {};
    logFile.LoggerName = const_cast<LPWSTR>(SESSION_NAME);
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;
    
    m_traceHandle = OpenTraceW(&logFile);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        return;
    }
    
    // This blocks until the trace is stopped
    ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
}

VOID WINAPI EtwMonitor::EventRecordCallback(PEVENT_RECORD pEventRecord) {
    if (!g_etwMonitor || !g_etwMonitor->m_running.load()) return;
    
    g_etwMonitor->HandleProcessEvent(pEventRecord);
}

void EtwMonitor::HandleProcessEvent(PEVENT_RECORD pEventRecord) {
    if (!IsEqualGUID(pEventRecord->EventHeader.ProviderId, KERNEL_PROCESS_GUID)) {
        return;
    }
    
    USHORT eventId = pEventRecord->EventHeader.EventDescriptor.Id;
    
    ProcessEvent event;
    event.timestamp = GetCurrentTimestamp();
    event.pid = pEventRecord->EventHeader.ProcessId;
    
    if (eventId == EVENT_ID_PROCESS_START) {
        event.eventType = EventType::ProcessCreated;
        
        // Get process info
        event.imagePath = GetProcessImagePath(event.pid);
        event.commandLine = GetProcessCommandLine(event.pid);
        
        // Try to get parent PID from event data
        if (pEventRecord->UserDataLength >= sizeof(DWORD)) {
            event.parentPid = *reinterpret_cast<DWORD*>(pEventRecord->UserData);
        }
        
        // Compute hash and verify signature
        if (!event.imagePath.empty()) {
            event.hashSha256 = ComputeFileHash(event.imagePath);
            event.isSigned = VerifySignature(event.imagePath, event.signer);
        }
    }
    else if (eventId == EVENT_ID_PROCESS_STOP) {
        event.eventType = EventType::ProcessTerminated;
    }
    else {
        return; // Ignore other events
    }
    
    if (m_callback) {
        m_callback(event);
    }
}

std::wstring EtwMonitor::GetProcessImagePath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return L"";
    
    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return path;
    }
    
    CloseHandle(hProcess);
    return L"";
}

std::wstring EtwMonitor::GetProcessCommandLine(DWORD pid) {
    // Note: Getting command line requires more complex code using NtQueryInformationProcess
    // For now, return empty - can be enhanced later
    UNREFERENCED_PARAMETER(pid);
    return L"";
}

std::wstring EtwMonitor::ComputeFileHash(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return L"";
    
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::wstring result;
    
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            BYTE buffer[8192];
            DWORD bytesRead;
            
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
                CryptHashData(hHash, buffer, bytesRead, 0);
            }
            
            BYTE hash[32];
            DWORD hashLen = 32;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                std::wstringstream ss;
                for (DWORD i = 0; i < hashLen; i++) {
                    ss << std::hex << std::setfill(L'0') << std::setw(2) << hash[i];
                }
                result = ss.str();
            }
            
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    CloseHandle(hFile);
    return result;
}

bool EtwMonitor::VerifySignature(const std::wstring& filePath, std::wstring& signerName) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    
    LONG status = WinVerifyTrust(nullptr, &policyGUID, &trustData);
    
    bool isSigned = (status == ERROR_SUCCESS);
    
    if (isSigned) {
        // Get signer info
        CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
        if (provData) {
            CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
            if (signer && signer->pasCertChain && signer->csCertChain > 0) {
                PCCERT_CONTEXT cert = signer->pasCertChain[0].pCert;
                if (cert) {
                    wchar_t name[256] = {};
                    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 256);
                    signerName = name;
                }
            }
        }
    }
    
    // Cleanup
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGUID, &trustData);
    
    return isSigned;
}
