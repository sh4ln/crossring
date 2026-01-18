// CROSSRING - Hash Utilities and Integrity Checker Implementation
#include "HashUtil.h"
#include <fstream>
#include <sstream>
#include <iomanip>

std::wstring HashUtil::ComputeHash(const std::wstring& filePath, LPCWSTR algorithm) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::wstring result;
    
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, algorithm, nullptr, 0))) {
        return L"";
    }
    
    DWORD hashObjSize = 0, hashSize = 0, dummy = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjSize, sizeof(DWORD), &dummy, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashSize, sizeof(DWORD), &dummy, 0);
    
    std::vector<BYTE> hashObj(hashObjSize);
    std::vector<BYTE> hash(hashSize);
    
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, nullptr, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return L"";
    }
    
    // Read file and hash
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        BYTE buffer[8192];
        DWORD bytesRead;
        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
            BCryptHashData(hHash, buffer, bytesRead, 0);
        }
        CloseHandle(hFile);
        
        if (BCRYPT_SUCCESS(BCryptFinishHash(hHash, hash.data(), hashSize, 0))) {
            result = BytesToHex(hash.data(), hashSize);
        }
    }
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

std::wstring HashUtil::ComputeSHA256(const std::wstring& filePath) {
    return ComputeHash(filePath, BCRYPT_SHA256_ALGORITHM);
}

// WARNING: SHA1 is cryptographically broken. Use ComputeSHA256 instead.
// This function exists only for legacy compatibility.
// [[deprecated("SHA1 is weak - use ComputeSHA256 for security")]]
std::wstring HashUtil::ComputeSHA1(const std::wstring& filePath) {
    return ComputeHash(filePath, BCRYPT_SHA1_ALGORITHM);
}

// WARNING: MD5 is cryptographically broken. Use ComputeSHA256 instead.
// This function exists only for legacy compatibility.
// [[deprecated("MD5 is weak - use ComputeSHA256 for security")]]
std::wstring HashUtil::ComputeMD5(const std::wstring& filePath) {
    return ComputeHash(filePath, BCRYPT_MD5_ALGORITHM);
}

std::wstring HashUtil::ComputeBufferSHA256(const void* buffer, size_t length) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::wstring result;
    
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
        return L"";
    }
    
    DWORD hashObjSize = 0, hashSize = 0, dummy = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjSize, sizeof(DWORD), &dummy, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashSize, sizeof(DWORD), &dummy, 0);
    
    std::vector<BYTE> hashObj(hashObjSize);
    std::vector<BYTE> hash(hashSize);
    
    if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, nullptr, 0, 0))) {
        BCryptHashData(hHash, (PBYTE)buffer, static_cast<ULONG>(length), 0);
        if (BCRYPT_SUCCESS(BCryptFinishHash(hHash, hash.data(), hashSize, 0))) {
            result = BytesToHex(hash.data(), hashSize);
        }
        BCryptDestroyHash(hHash);
    }
    
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

HashUtil::FileHashes HashUtil::ComputeAllHashes(const std::wstring& filePath) {
    FileHashes hashes;
    hashes.sha256 = ComputeSHA256(filePath);
    hashes.sha1 = ComputeSHA1(filePath);
    hashes.md5 = ComputeMD5(filePath);
    
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fad)) {
        hashes.fileSize = (static_cast<uint64_t>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
    }
    
    return hashes;
}

bool HashUtil::VerifyFileIntegrity(const std::wstring& filePath, const std::wstring& expectedHash) {
    std::wstring actualHash = ComputeSHA256(filePath);
    return _wcsicmp(actualHash.c_str(), expectedHash.c_str()) == 0;
}

std::wstring HashUtil::BytesToHex(const BYTE* bytes, size_t length) {
    std::wstringstream ss;
    for (size_t i = 0; i < length; i++) {
        ss << std::hex << std::setfill(L'0') << std::setw(2) << bytes[i];
    }
    return ss.str();
}

// IntegrityChecker implementation
IntegrityChecker& IntegrityChecker::Instance() {
    static IntegrityChecker instance;
    return instance;
}

std::wstring IntegrityChecker::GetBaselinePath() {
    return std::wstring(DATA_DIR) + L"\\baseline.dat";
}

bool IntegrityChecker::Initialize() {
    return LoadBaseline();
}

bool IntegrityChecker::LoadBaseline() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_baseline.clear();
    
    std::wifstream file(GetBaselinePath());
    if (!file.is_open()) return true; // No baseline yet
    
    std::wstring line;
    while (std::getline(file, line)) {
        size_t sep = line.find(L'|');
        if (sep != std::wstring::npos) {
            std::wstring path = line.substr(0, sep);
            std::wstring hash = line.substr(sep + 1);
            
            // FIX #5: Normalize path to prevent traversal attacks
            wchar_t canonical[MAX_PATH] = {0};
            if (GetFullPathNameW(path.c_str(), MAX_PATH, canonical, nullptr) > 0) {
                m_baseline[canonical] = hash;
            } else {
                // Invalid path, skip this entry
                continue;
            }
        }
    }
    return true;
}

bool IntegrityChecker::SaveBaseline() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::wofstream file(GetBaselinePath());
    if (!file.is_open()) return false;
    
    for (const auto& [path, hash] : m_baseline) {
        file << path << L"|" << hash << L"\n";
    }
    return true;
}

bool IntegrityChecker::StoreBaseline(const std::wstring& filePath) {
    std::wstring hash = HashUtil::ComputeSHA256(filePath);
    if (hash.empty()) return false;
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_baseline[filePath] = hash;
    }
    return SaveBaseline();
}

bool IntegrityChecker::VerifyIntegrity(const std::wstring& filePath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_baseline.find(filePath);
    if (it == m_baseline.end()) return true; // Not baselined
    
    std::wstring actualHash = HashUtil::ComputeSHA256(filePath);
    if (actualHash != it->second) {
        if (m_callback) {
            TamperEvent event;
            event.filePath = filePath;
            event.expectedHash = it->second;
            event.actualHash = actualHash;
            event.timestamp = GetCurrentTimestamp();
            m_callback(event);
        }
        return false;
    }
    return true;
}

bool IntegrityChecker::VerifyServiceIntegrity() {
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    return VerifyIntegrity(modulePath);
}

bool IntegrityChecker::VerifyConfigIntegrity() {
    return VerifyIntegrity(CONFIG_PATH);
}
