#pragma once
#include "Common.h"

class ServiceController {
public:
    static ServiceController& Instance();
    
    // Service lifecycle
    bool Initialize();
    void Run();
    void Stop();
    
    // Status
    bool IsRunning() const { return m_running.load(); }
    
    // Service control handler
    static DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD dwEventType,
                                            LPVOID lpEventData, LPVOID lpContext);
    static VOID WINAPI ServiceMain(DWORD dwArgc, LPWSTR* lpszArgv);

private:
    ServiceController() = default;
    ~ServiceController() = default;
    ServiceController(const ServiceController&) = delete;
    ServiceController& operator=(const ServiceController&) = delete;
    
    void SetServiceStatus(DWORD currentState, DWORD win32ExitCode = NO_ERROR,
                          DWORD waitHint = 0);
    void WorkerThread();
    
    SERVICE_STATUS m_serviceStatus{};
    SERVICE_STATUS_HANDLE m_statusHandle = nullptr;
    HANDLE m_stopEvent = nullptr;
    std::atomic<bool> m_running{false};
    std::unique_ptr<std::thread> m_workerThread;
};

// Helper to install/uninstall service
bool InstallService();
bool UninstallService();
bool StartServiceManually();
