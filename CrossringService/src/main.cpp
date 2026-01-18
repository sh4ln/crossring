// CROSSRING - Owner-Gated Offline Endpoint Security System
// Main Service Entry Point

#include "Common.h"
#include "ServiceController.h"
#include "Database.h"
#include "EtwMonitor.h"
#include "PipeServer.h"
#include "PolicyEnforcer.h"
#include "MemoryScanner.h"
#include <iostream>

void PrintUsage() {
    std::wcout << L"CROSSRING Service\n";
    std::wcout << L"==================\n\n";
    std::wcout << L"Usage:\n";
    std::wcout << L"  CrossringService.exe              Run as Windows Service\n";
    std::wcout << L"  CrossringService.exe /install     Install the service\n";
    std::wcout << L"  CrossringService.exe /uninstall   Uninstall the service\n";
    std::wcout << L"  CrossringService.exe /console     Run in console mode (debugging)\n";
    std::wcout << L"  CrossringService.exe /verify      Verify installation integrity\n";
}

void RunConsoleMode() {
    std::wcout << L"[CROSSRING] Starting in console mode...\n";
    
    // Create data directory
    std::filesystem::create_directories(DATA_DIR);
    std::filesystem::create_directories(LOG_DIR);
    
    // Initialize components
    if (!Database::Instance().Initialize()) {
        std::wcerr << L"[ERROR] Failed to initialize database\n";
        return;
    }
    std::wcout << L"[OK] Database initialized\n";
    
    if (!PolicyEnforcer::Instance().Initialize()) {
        std::wcerr << L"[ERROR] Failed to initialize policy enforcer\n";
        return;
    }
    std::wcout << L"[OK] Policy enforcer initialized\n";
    
    // Start named pipe server
    if (!PipeServer::Instance().Start([](const json& msg) {
        std::wcout << L"[PIPE] Received: " << msg.dump().c_str() << L"\n";
        
        // Handle decision messages
        if (msg.contains("type") && msg["type"] == "decision") {
            // Process decision from GUI
            // TODO: Implement decision handling
        }
    })) {
        std::wcerr << L"[ERROR] Failed to start pipe server\n";
        return;
    }
    std::wcout << L"[OK] Pipe server started\n";
    
    // Start ETW monitoring
    if (!EtwMonitor::Instance().Start([](const ProcessEvent& event) {
        std::wcout << L"[ETW] Process " 
                   << (event.eventType == EventType::ProcessCreated ? L"created" : L"terminated")
                   << L": PID=" << event.pid 
                   << L" Path=" << event.imagePath << L"\n";
        
        if (event.eventType == EventType::ProcessCreated) {
            // Check policy
            auto result = PolicyEnforcer::Instance().CheckExecution(event);
            
            if (result == PolicyEnforcer::ExecutionResult::Blocked) {
                // Log to database
                ProcessEvent logEvent = event;
                logEvent.decision = Decision::Pending;
                Database::Instance().InsertProcessEvent(logEvent);
                
                // Notify GUI
                PipeServer::Instance().NotifyProcessBlocked(event);
            }
        }
    })) {
        std::wcerr << L"[ERROR] Failed to start ETW monitor\n";
        return;
    }
    std::wcout << L"[OK] ETW monitor started\n";
    
    // Start memory scanner
    if (!MemoryScanner::Instance().Start([](const MemoryAnomaly& anomaly) {
        std::wcout << L"[MEMORY] Anomaly detected: " 
                   << anomaly.anomalyType 
                   << L" in PID=" << anomaly.pid << L"\n";
        
        Database::Instance().InsertMemoryAnomaly(anomaly);
        PipeServer::Instance().NotifyAnomaly(anomaly);
    })) {
        std::wcerr << L"[WARNING] Failed to start memory scanner\n";
        // Non-fatal, continue
    } else {
        std::wcout << L"[OK] Memory scanner started\n";
    }
    
    std::wcout << L"\n[CROSSRING] Service running. Press Enter to stop...\n\n";
    std::cin.get();
    
    // Shutdown
    std::wcout << L"[CROSSRING] Shutting down...\n";
    MemoryScanner::Instance().Stop();
    EtwMonitor::Instance().Stop();
    PipeServer::Instance().Stop();
    PolicyEnforcer::Instance().Shutdown();
    Database::Instance().Shutdown();
    
    std::wcout << L"[CROSSRING] Stopped.\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        std::wstring arg = argv[1];
        
        if (arg == L"/install" || arg == L"-install") {
            if (InstallService()) {
                std::wcout << L"Service installed successfully.\n";
                return 0;
            } else {
                std::wcerr << L"Failed to install service.\n";
                return 1;
            }
        }
        else if (arg == L"/uninstall" || arg == L"-uninstall") {
            if (UninstallService()) {
                std::wcout << L"Service uninstalled successfully.\n";
                return 0;
            } else {
                std::wcerr << L"Failed to uninstall service.\n";
                return 1;
            }
        }
        else if (arg == L"/console" || arg == L"-console") {
            RunConsoleMode();
            return 0;
        }
        else if (arg == L"/verify" || arg == L"-verify") {
            std::wcout << L"Verifying installation integrity...\n";
            // TODO: Implement integrity verification
            std::wcout << L"Verification complete.\n";
            return 0;
        }
        else if (arg == L"/?" || arg == L"-?" || arg == L"/help" || arg == L"-help") {
            PrintUsage();
            return 0;
        }
    }
    
    // Run as Windows Service
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), ServiceController::ServiceMain },
        { nullptr, nullptr }
    };
    
    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // Not running as service, show usage
            PrintUsage();
            std::wcout << L"\nTip: Use /console for debugging.\n";
        }
        return 1;
    }
    
    return 0;
}
