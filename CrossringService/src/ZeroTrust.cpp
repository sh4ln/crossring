// CROSSRING - Zero Trust Security Engine
#include "ZeroTrust.h"
#include "HashUtil.h"
#include <algorithm>

ZeroTrustEngine& ZeroTrustEngine::Instance() {
    static ZeroTrustEngine instance;
    return instance;
}

bool ZeroTrustEngine::Initialize() {
    // Load known bad hashes from offline database
    // In production, this would load from a file
    m_knownBadHashes = {
        // Example IOCs (these are fake for demonstration)
        L"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    };
    
    // Suspicious paths
    m_suspiciousPaths = {
        L"\\temp\\",
        L"\\tmp\\",
        L"\\appdata\\local\\temp\\",
        L"\\downloads\\",
        L"\\public\\",
        L"\\users\\public\\",
        L"\\programdata\\",
        L"\\$recycle.bin\\",
        L":\\users\\",  // Direct execution from user profile
    };
    
    // Suspicious command line patterns
    m_suspiciousCmdPatterns = {
        L"-enc ", L"-encodedcommand",
        L"-nop ", L"-noprofile",
        L"-w hidden", L"-windowstyle hidden",
        L"-exec bypass", L"-executionpolicy bypass",
        L"iex(", L"invoke-expression",
        L"downloadstring", L"downloadfile",
        L"webclient", L"webrequest",
        L"bitsadmin", L"/transfer",
        L"certutil", L"-urlcache",
        L"mshta", L"vbscript:",
        L"regsvr32", L"/s /n /u",
        L"rundll32", L"javascript:",
    };
    
    return true;
}

ZeroTrustEngine::TrustEvaluation ZeroTrustEngine::EvaluateProcess(const ProcessEvent& event) {
    TrustEvaluation result;
    result.level = TrustLevel::Untrusted;
    result.riskScore = 0;
    result.requiresAuth = false;
    
    // === RISK FACTORS ===
    
    // 1. Check for known bad hash
    if (HasKnownBadHash(event.hashSha256)) {
        result.riskScore += RiskFactors::KNOWN_BAD_HASH;
        result.riskFactors.push_back(L"Known malicious file hash");
    }
    
    // 2. Unsigned executable
    if (!event.isSigned) {
        result.riskScore += RiskFactors::UNSIGNED_EXECUTABLE;
        result.riskFactors.push_back(L"Unsigned executable");
    }
    
    // 3. Suspicious path
    if (HasSuspiciousPath(event.imagePath)) {
        result.riskScore += RiskFactors::TEMP_FOLDER;
        result.riskFactors.push_back(L"Running from suspicious location");
    }
    
    // 4. USB drive
    if (IsFromUntrustedLocation(event.imagePath)) {
        result.riskScore += RiskFactors::USB_DRIVE;
        result.riskFactors.push_back(L"Running from removable drive");
    }
    
    // 5. Suspicious command line
    if (HasSuspiciousCommandLine(event.commandLine)) {
        result.riskScore += RiskFactors::LOLBIN_ABUSE;
        result.riskFactors.push_back(L"Suspicious command line arguments");
    }
    
    // 6. Check if it's a LOLBin with unusual behavior
    std::wstring lowerPath = event.imagePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    
    std::vector<std::wstring> lolbins = {
        L"powershell", L"cmd.exe", L"wscript", L"cscript",
        L"mshta", L"certutil", L"rundll32", L"regsvr32",
        L"bitsadmin", L"msiexec", L"wmic"
    };
    
    for (const auto& lolbin : lolbins) {
        if (lowerPath.find(lolbin) != std::wstring::npos) {
            result.riskScore += 15;
            result.riskFactors.push_back(L"LOLBin execution: " + lolbin);
            break;
        }
    }
    
    // === TRUST FACTORS ===
    
    // 1. Microsoft signed
    if (event.isSigned) {
        std::wstring lowerSigner = event.signer;
        std::transform(lowerSigner.begin(), lowerSigner.end(), lowerSigner.begin(), ::towlower);
        
        if (lowerSigner.find(L"microsoft") != std::wstring::npos) {
            result.riskScore += TrustFactors::MICROSOFT_SIGNED;
            result.trustFactors.push_back(L"Microsoft signed");
        } else {
            result.riskScore += TrustFactors::KNOWN_PUBLISHER;
            result.trustFactors.push_back(L"Signed by: " + event.signer);
        }
    }
    
    // 2. System path
    if (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos ||
        lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos) {
        result.riskScore += TrustFactors::SYSTEM_PATH;
        result.trustFactors.push_back(L"System directory");
    }
    
    // === CALCULATE TRUST LEVEL ===
    
    if (result.riskScore >= 80) {
        result.level = TrustLevel::Untrusted;
        result.requiresAuth = true;
    } else if (result.riskScore >= 50) {
        result.level = TrustLevel::LowTrust;
        result.requiresAuth = true;
    } else if (result.riskScore >= 20) {
        result.level = TrustLevel::MediumTrust;
        result.requiresAuth = false;
    } else if (result.riskScore >= 0) {
        result.level = TrustLevel::HighTrust;
        result.requiresAuth = false;
    }
    
    // System processes get maximum trust
    if (event.imagePath.find(L"\\Windows\\") != std::wstring::npos && event.isSigned) {
        result.level = TrustLevel::SystemTrust;
        result.requiresAuth = false;
    }
    
    // Clamp risk score
    result.riskScore = std::max(0, std::min(100, result.riskScore));
    
    return result;
}

ZeroTrustEngine::TrustEvaluation ZeroTrustEngine::EvaluateScript(
    const std::wstring& content, const std::wstring& source) {
    
    TrustEvaluation result;
    result.level = TrustLevel::Untrusted;
    result.riskScore = 30;  // Scripts start with higher suspicion
    result.requiresAuth = true;
    
    std::wstring lower = content;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    // Check for obfuscation indicators
    int obfuscationScore = 0;
    
    if (lower.find(L"frombase64") != std::wstring::npos) obfuscationScore += 10;
    if (lower.find(L"-join") != std::wstring::npos) obfuscationScore += 5;
    if (lower.find(L"[char]") != std::wstring::npos) obfuscationScore += 10;
    if (lower.find(L"-replace") != std::wstring::npos) obfuscationScore += 5;
    if (lower.find(L"-bxor") != std::wstring::npos) obfuscationScore += 15;
    if (lower.find(L"gzipstream") != std::wstring::npos) obfuscationScore += 15;
    
    if (obfuscationScore > 20) {
        result.riskScore += RiskFactors::OBFUSCATED_SCRIPT;
        result.riskFactors.push_back(L"Heavily obfuscated script");
    }
    
    return result;
}

ZeroTrustEngine::TrustEvaluation ZeroTrustEngine::EvaluateNetwork(const NetworkEvent& event) {
    TrustEvaluation result;
    result.level = TrustLevel::MediumTrust;
    result.riskScore = 0;
    result.requiresAuth = false;
    
    // Internet connection from unknown process
    if (event.remoteAddr.find(L"192.168.") != 0 &&
        event.remoteAddr.find(L"10.") != 0 &&
        event.remoteAddr.find(L"172.") != 0 &&
        event.remoteAddr != L"127.0.0.1") {
        
        result.riskScore += RiskFactors::NETWORK_TO_INTERNET;
        result.riskFactors.push_back(L"External network connection");
    }
    
    // Suspicious ports
    std::vector<uint16_t> suspiciousPorts = { 4444, 5555, 6666, 8888, 9999, 31337 };
    for (uint16_t port : suspiciousPorts) {
        if (event.remotePort == port) {
            result.riskScore += RiskFactors::SUSPICIOUS_PORT;
            result.riskFactors.push_back(L"Connection to suspicious port");
            break;
        }
    }
    
    return result;
}

void ZeroTrustEngine::RecordBehavior(DWORD pid, const std::wstring& action) {
    std::lock_guard<std::mutex> lock(m_behaviorMutex);
    
    auto& behavior = m_behaviors[pid];
    behavior.pid = pid;
    behavior.actions.push_back(action);
    behavior.lastSeen = std::chrono::steady_clock::now();
    
    // Track suspicious actions
    std::wstring lower = action;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    if (lower.find(L"inject") != std::wstring::npos ||
        lower.find(L"hook") != std::wstring::npos ||
        lower.find(L"dump") != std::wstring::npos) {
        behavior.suspiciousActionCount++;
    }
}

bool ZeroTrustEngine::HasSuspiciousBehavior(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_behaviorMutex);
    
    auto it = m_behaviors.find(pid);
    if (it == m_behaviors.end()) return false;
    
    return it->second.suspiciousActionCount >= 3;
}

bool ZeroTrustEngine::VerifyContinuously(DWORD pid) {
    // Re-verify process hasn't been modified
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;
    
    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    QueryFullProcessImageNameW(hProcess, 0, path, &size);
    CloseHandle(hProcess);
    
    // Re-hash and verify
    std::wstring hash = HashUtil::ComputeSHA256(path);
    
    // TODO: Compare with original hash from whitelist
    
    return true;
}

bool ZeroTrustEngine::HasKnownBadHash(const std::wstring& hash) {
    return m_knownBadHashes.find(hash) != m_knownBadHashes.end();
}

bool ZeroTrustEngine::HasSuspiciousPath(const std::wstring& path) {
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    for (const auto& suspicious : m_suspiciousPaths) {
        if (lower.find(suspicious) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

bool ZeroTrustEngine::HasSuspiciousCommandLine(const std::wstring& cmdLine) {
    std::wstring lower = cmdLine;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    int matches = 0;
    for (const auto& pattern : m_suspiciousCmdPatterns) {
        if (lower.find(pattern) != std::wstring::npos) {
            matches++;
            if (matches >= 2) return true;  // Two or more suspicious patterns
        }
    }
    return false;
}

bool ZeroTrustEngine::IsFromUntrustedLocation(const std::wstring& path) {
    if (path.length() < 3) return false;
    
    // Check if it's a removable drive
    std::wstring root = path.substr(0, 3);
    UINT driveType = GetDriveTypeW(root.c_str());
    
    return driveType == DRIVE_REMOVABLE || driveType == DRIVE_REMOTE;
}
