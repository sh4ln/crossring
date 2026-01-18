#pragma once
#include "Common.h"
#include <dbt.h>

class UsbMonitor {
public:
    static UsbMonitor& Instance();
    
    bool Initialize(HWND hwnd = nullptr);
    void Shutdown();
    
    struct UsbDevice {
        std::wstring deviceId;
        std::wstring volumePath;
        std::wstring label;
        std::wstring timestamp;
        bool executionBlocked;
    };
    
    using UsbCallback = std::function<void(const UsbDevice&, bool connected)>;
    void SetCallback(UsbCallback callback) { m_callback = callback; }
    
    // Block execution on USB drives
    bool BlockUsbExecution(const std::wstring& volumePath);
    bool AllowUsbExecution(const std::wstring& volumePath);
    
    // Check if path is on USB
    bool IsUsbPath(const std::wstring& path);
    
    // Get connected USB drives
    std::vector<UsbDevice> GetConnectedDrives();
    
    // Process device notification
    LRESULT OnDeviceChange(WPARAM wParam, LPARAM lParam);
    
private:
    UsbMonitor() = default;
    
    UsbCallback m_callback;
    HDEVNOTIFY m_deviceNotify = nullptr;
    
    std::vector<std::wstring> m_blockedVolumes;
    std::vector<std::wstring> m_allowedVolumes;
    std::mutex m_mutex;
    
    std::wstring GetVolumeLabel(const std::wstring& volumePath);
    bool IsRemovableDrive(const std::wstring& path);
};
