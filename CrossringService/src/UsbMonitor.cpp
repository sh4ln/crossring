// CROSSRING - USB Monitor Implementation
#include "UsbMonitor.h"

UsbMonitor& UsbMonitor::Instance() {
    static UsbMonitor instance;
    return instance;
}

bool UsbMonitor::Initialize(HWND hwnd) {
    if (hwnd) {
        DEV_BROADCAST_DEVICEINTERFACE filter = {};
        filter.dbcc_size = sizeof(filter);
        filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        
        m_deviceNotify = RegisterDeviceNotificationW(hwnd, &filter,
            DEVICE_NOTIFY_WINDOW_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);
    }
    
    // Block all removable drives by default
    auto drives = GetConnectedDrives();
    for (const auto& drive : drives) {
        BlockUsbExecution(drive.volumePath);
    }
    
    return true;
}

void UsbMonitor::Shutdown() {
    if (m_deviceNotify) {
        UnregisterDeviceNotification(m_deviceNotify);
        m_deviceNotify = nullptr;
    }
}

LRESULT UsbMonitor::OnDeviceChange(WPARAM wParam, LPARAM lParam) {
    if (wParam == DBT_DEVICEARRIVAL) {
        auto* header = reinterpret_cast<DEV_BROADCAST_HDR*>(lParam);
        if (header->dbch_devicetype == DBT_DEVTYP_VOLUME) {
            auto* volume = reinterpret_cast<DEV_BROADCAST_VOLUME*>(lParam);
            
            // Find the drive letter
            for (int i = 0; i < 26; i++) {
                if (volume->dbcv_unitmask & (1 << i)) {
                    wchar_t drivePath[4] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', 0 };
                    
                    if (IsRemovableDrive(drivePath)) {
                        UsbDevice device;
                        device.volumePath = drivePath;
                        device.label = GetVolumeLabel(drivePath);
                        device.timestamp = GetCurrentTimestamp();
                        device.executionBlocked = true;
                        
                        BlockUsbExecution(drivePath);
                        
                        if (m_callback) m_callback(device, true);
                    }
                }
            }
        }
    }
    else if (wParam == DBT_DEVICEREMOVECOMPLETE) {
        auto* header = reinterpret_cast<DEV_BROADCAST_HDR*>(lParam);
        if (header->dbch_devicetype == DBT_DEVTYP_VOLUME) {
            auto* volume = reinterpret_cast<DEV_BROADCAST_VOLUME*>(lParam);
            
            for (int i = 0; i < 26; i++) {
                if (volume->dbcv_unitmask & (1 << i)) {
                    wchar_t drivePath[4] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', 0 };
                    
                    UsbDevice device;
                    device.volumePath = drivePath;
                    device.timestamp = GetCurrentTimestamp();
                    
                    if (m_callback) m_callback(device, false);
                    
                    // Remove from lists
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_blockedVolumes.erase(
                        std::remove(m_blockedVolumes.begin(), m_blockedVolumes.end(), drivePath),
                        m_blockedVolumes.end());
                    m_allowedVolumes.erase(
                        std::remove(m_allowedVolumes.begin(), m_allowedVolumes.end(), drivePath),
                        m_allowedVolumes.end());
                }
            }
        }
    }
    
    return TRUE;
}

bool UsbMonitor::BlockUsbExecution(const std::wstring& volumePath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_allowedVolumes.erase(
        std::remove(m_allowedVolumes.begin(), m_allowedVolumes.end(), volumePath),
        m_allowedVolumes.end());
    
    if (std::find(m_blockedVolumes.begin(), m_blockedVolumes.end(), volumePath) == m_blockedVolumes.end()) {
        m_blockedVolumes.push_back(volumePath);
    }
    
    return true;
}

bool UsbMonitor::AllowUsbExecution(const std::wstring& volumePath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_blockedVolumes.erase(
        std::remove(m_blockedVolumes.begin(), m_blockedVolumes.end(), volumePath),
        m_blockedVolumes.end());
    
    if (std::find(m_allowedVolumes.begin(), m_allowedVolumes.end(), volumePath) == m_allowedVolumes.end()) {
        m_allowedVolumes.push_back(volumePath);
    }
    
    return true;
}

bool UsbMonitor::IsUsbPath(const std::wstring& path) {
    if (path.length() < 3) return false;
    
    std::wstring root = path.substr(0, 3);
    if (root[1] != L':') return false;
    
    // Check if removable
    if (!IsRemovableDrive(root)) return false;
    
    // Check if blocked
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& blocked : m_blockedVolumes) {
        if (_wcsnicmp(path.c_str(), blocked.c_str(), blocked.length()) == 0) {
            return true;
        }
    }
    
    return false;
}

std::vector<UsbMonitor::UsbDevice> UsbMonitor::GetConnectedDrives() {
    std::vector<UsbDevice> drives;
    
    DWORD driveMask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (driveMask & (1 << i)) {
            wchar_t drivePath[4] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', 0 };
            
            if (IsRemovableDrive(drivePath)) {
                UsbDevice device;
                device.volumePath = drivePath;
                device.label = GetVolumeLabel(drivePath);
                device.timestamp = GetCurrentTimestamp();
                
                std::lock_guard<std::mutex> lock(m_mutex);
                device.executionBlocked = std::find(m_blockedVolumes.begin(), m_blockedVolumes.end(), drivePath) != m_blockedVolumes.end();
                
                drives.push_back(device);
            }
        }
    }
    
    return drives;
}

std::wstring UsbMonitor::GetVolumeLabel(const std::wstring& volumePath) {
    wchar_t label[MAX_PATH] = {};
    GetVolumeInformationW(volumePath.c_str(), label, MAX_PATH, nullptr, nullptr, nullptr, nullptr, 0);
    return label;
}

bool UsbMonitor::IsRemovableDrive(const std::wstring& path) {
    return GetDriveTypeW(path.c_str()) == DRIVE_REMOVABLE;
}
