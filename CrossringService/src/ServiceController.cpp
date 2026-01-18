// CROSSRING - Service Controller Implementation
#include "ServiceController.h"
#include "Database.h"
#include "EtwMonitor.h"
#include "PipeServer.h"
#include "PolicyEnforcer.h"
#include "MemoryScanner.h"
#include <filesystem>

ServiceController& ServiceController::Instance() {
    static ServiceController instance;
    return instance;
}

bool ServiceController::Initialize() {
    // Create data directories
    try {
        std::filesystem::create_directories(DATA_DIR);
        std::filesystem::create_directories(LOG_DIR);
    } catch (...) {
        return false;
    }
    
    // Initialize database
    if (!Database::Instance().Initialize()) {
        return false;
    }
    
    // Initialize policy enforcer
    if (!PolicyEnforcer::Instance().Initialize()) {
        return false;
    }
    
    return true;
}

void ServiceController::Run() {
    m_running = true;
    
    // Start pipe server for GUI communication
    PipeServer::Instance().Start([this](const json& msg) {
        if (msg.contains("type")) {
            std::string type = msg["type"];
            if (type == "decision") {
                // Handle user decision
                uint64_t eventId = msg.value("event_id", 0ULL);
                std::string action = msg.value("action", "deny");
                std::string scope = msg.value("scope", "once");
                
                Decision decision = Decision::Deny;
                if (action == "allow") {
                    if (scope == "permanent") decision = Decision::AllowPermanent;
                    else if (scope == "session") decision = Decision::AllowSession;
                    else decision = Decision::AllowOnce;
                }
                
                Database::Instance().UpdateProcessDecision(eventId, decision, L"User decision");
            }
        }
    });
    
    // Start ETW process monitoring
    EtwMonitor::Instance().Start([](const ProcessEvent& event) {
        if (event.eventType == EventType::ProcessCreated) {
            auto result = PolicyEnforcer::Instance().CheckExecution(event);
            
            if (result == PolicyEnforcer::ExecutionResult::Blocked) {
                ProcessEvent logEvent = event;
                logEvent.decision = Decision::Pending;
                uint64_t id = Database::Instance().InsertProcessEvent(logEvent);
                
                // Notify GUI
                ProcessEvent notifyEvent = logEvent;
                notifyEvent.id = id;
                PipeServer::Instance().NotifyProcessBlocked(notifyEvent);
            } else {
                ProcessEvent logEvent = event;
                logEvent.decision = Decision::AllowPermanent;
                logEvent.decisionReason = L"Whitelisted or system process";
                Database::Instance().InsertProcessEvent(logEvent);
            }
        }
    });
    
    // Start memory scanner
    MemoryScanner::Instance().Start([](const MemoryAnomaly& anomaly) {
        Database::Instance().InsertMemoryAnomaly(anomaly);
        PipeServer::Instance().NotifyAnomaly(anomaly);
    });
    
    // Worker thread for periodic tasks
    m_workerThread = std::make_unique<std::thread>(&ServiceController::WorkerThread, this);
}

void ServiceController::Stop() {
    m_running = false;
    
    if (m_stopEvent) {
        SetEvent(m_stopEvent);
    }
    
    if (m_workerThread && m_workerThread->joinable()) {
        m_workerThread->join();
    }
    
    MemoryScanner::Instance().Stop();
    EtwMonitor::Instance().Stop();
    PipeServer::Instance().Stop();
    PolicyEnforcer::Instance().Shutdown();
    Database::Instance().Shutdown();
}

void ServiceController::WorkerThread() {
    while (m_running) {
        // Periodic database maintenance
        Database::Instance().PruneOldEvents(90);
        
        // Sleep for 1 hour
        for (int i = 0; i < 3600 && m_running; ++i) {
            Sleep(1000);
        }
    }
}

void ServiceController::SetServiceStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint) {
    static DWORD checkPoint = 1;
    
    m_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_serviceStatus.dwCurrentState = currentState;
    m_serviceStatus.dwWin32ExitCode = win32ExitCode;
    m_serviceStatus.dwWaitHint = waitHint;
    
    if (currentState == SERVICE_START_PENDING) {
        m_serviceStatus.dwControlsAccepted = 0;
    } else {
        m_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }
    
    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        m_serviceStatus.dwCheckPoint = 0;
    } else {
        m_serviceStatus.dwCheckPoint = checkPoint++;
    }
    
    ::SetServiceStatus(m_statusHandle, &m_serviceStatus);
}

DWORD WINAPI ServiceController::ServiceCtrlHandler(DWORD dwControl, DWORD, LPVOID, LPVOID) {
    switch (dwControl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            Instance().SetServiceStatus(SERVICE_STOP_PENDING);
            Instance().Stop();
            Instance().SetServiceStatus(SERVICE_STOPPED);
            return NO_ERROR;
            
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
            
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

VOID WINAPI ServiceController::ServiceMain(DWORD, LPWSTR*) {
    auto& svc = Instance();
    
    svc.m_statusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceCtrlHandler, nullptr);
    if (!svc.m_statusHandle) {
        return;
    }
    
    svc.SetServiceStatus(SERVICE_START_PENDING);
    
    svc.m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!svc.m_stopEvent) {
        svc.SetServiceStatus(SERVICE_STOPPED, GetLastError());
        return;
    }
    
    if (!svc.Initialize()) {
        svc.SetServiceStatus(SERVICE_STOPPED, GetLastError());
        return;
    }
    
    svc.SetServiceStatus(SERVICE_RUNNING);
    svc.Run();
    
    WaitForSingleObject(svc.m_stopEvent, INFINITE);
    
    CloseHandle(svc.m_stopEvent);
    svc.m_stopEvent = nullptr;
}

// Service installation helpers
bool InstallService() {
    wchar_t modulePath[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, modulePath, MAX_PATH)) {
        return false;
    }
    
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) {
        return false;
    }
    
    SC_HANDLE service = CreateServiceW(
        scManager,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        modulePath,
        nullptr, nullptr, nullptr, nullptr, nullptr
    );
    
    if (!service) {
        CloseServiceHandle(scManager);
        return false;
    }
    
    // Set description
    SERVICE_DESCRIPTIONW desc;
    desc.lpDescription = const_cast<LPWSTR>(CROSSRING_SERVICE_DESC);
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc);
    
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return true;
}

bool UninstallService() {
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) return false;
    
    SC_HANDLE service = OpenServiceW(scManager, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (!service) {
        CloseServiceHandle(scManager);
        return false;
    }
    
    SERVICE_STATUS status;
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    Sleep(1000);
    
    BOOL result = DeleteService(service);
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return result != FALSE;
}

bool StartServiceManually() {
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) return false;
    
    SC_HANDLE service = OpenServiceW(scManager, SERVICE_NAME, SERVICE_START);
    if (!service) {
        CloseServiceHandle(scManager);
        return false;
    }
    
    BOOL result = StartServiceW(service, 0, nullptr);
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return result != FALSE;
}
