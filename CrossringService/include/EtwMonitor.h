#pragma once
#include "Common.h"
#include <evntrace.h>
#include <evntcons.h>

class EtwMonitor {
public:
    static EtwMonitor& Instance();
    
    using ProcessCallback = std::function<void(const ProcessEvent&)>;
    
    bool Start(ProcessCallback callback);
    void Stop();
    bool IsRunning() const { return m_running.load(); }
    
private:
    EtwMonitor() = default;
    ~EtwMonitor();
    EtwMonitor(const EtwMonitor&) = delete;
    EtwMonitor& operator=(const EtwMonitor&) = delete;
    
    static VOID WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord);
    void ProcessThread();
    
    // ETW session management
    bool StartTraceSession();
    void StopTraceSession();
    
    // Event parsing
    void HandleProcessEvent(PEVENT_RECORD pEventRecord);
    std::wstring GetProcessImagePath(DWORD pid);
    std::wstring GetProcessCommandLine(DWORD pid);
    std::wstring ComputeFileHash(const std::wstring& filePath);
    bool VerifySignature(const std::wstring& filePath, std::wstring& signerName);
    
    ProcessCallback m_callback;
    std::atomic<bool> m_running{false};
    std::unique_ptr<std::thread> m_processThread;
    
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    
    // ETW session properties
    std::vector<BYTE> m_sessionProperties;
    
    // Session name
    static constexpr const wchar_t* SESSION_NAME = L"CrossringEtwSession";
    
    // Microsoft-Windows-Kernel-Process provider GUID
    // {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
    static constexpr GUID KERNEL_PROCESS_GUID = 
        { 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };
};
