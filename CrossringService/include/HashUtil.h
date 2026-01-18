#pragma once
#include "Common.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

class HashUtil {
public:
    // Multiple hash algorithms
    static std::wstring ComputeSHA256(const std::wstring& filePath);
    static std::wstring ComputeSHA1(const std::wstring& filePath);
    static std::wstring ComputeMD5(const std::wstring& filePath);
    
    // Hash buffer
    static std::wstring ComputeBufferSHA256(const void* buffer, size_t length);
    
    // Combined hash info
    struct FileHashes {
        std::wstring sha256;
        std::wstring sha1;
        std::wstring md5;
        uint64_t fileSize;
    };
    
    static FileHashes ComputeAllHashes(const std::wstring& filePath);
    
    // Integrity verification
    static bool VerifyFileIntegrity(const std::wstring& filePath, const std::wstring& expectedHash);
    
private:
    static std::wstring ComputeHash(const std::wstring& filePath, LPCWSTR algorithm);
    static std::wstring BytesToHex(const BYTE* bytes, size_t length);
};

class IntegrityChecker {
public:
    static IntegrityChecker& Instance();
    
    bool Initialize();
    
    // Store baseline hashes
    bool StoreBaseline(const std::wstring& filePath);
    bool VerifyIntegrity(const std::wstring& filePath);
    
    // Self-protection
    bool VerifyServiceIntegrity();
    bool VerifyConfigIntegrity();
    
    // Tamper detection
    struct TamperEvent {
        std::wstring filePath;
        std::wstring expectedHash;
        std::wstring actualHash;
        std::wstring timestamp;
    };
    
    using TamperCallback = std::function<void(const TamperEvent&)>;
    void SetTamperCallback(TamperCallback callback) { m_callback = callback; }
    
private:
    IntegrityChecker() = default;
    
    std::unordered_map<std::wstring, std::wstring> m_baseline;
    std::mutex m_mutex;
    TamperCallback m_callback;
    
    std::wstring GetBaselinePath();
    bool LoadBaseline();
    bool SaveBaseline();
};
