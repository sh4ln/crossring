// CROSSRING - Policy Enforcer Implementation
#include "PolicyEnforcer.h"
#include "Database.h"
#include <algorithm>
#include <cctype>

PolicyEnforcer& PolicyEnforcer::Instance() {
    static PolicyEnforcer instance;
    return instance;
}

bool PolicyEnforcer::Initialize() {
    LoadLolBinPatterns();
    return true;
}

void PolicyEnforcer::Shutdown() {
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    m_sessionAllowed.clear();
}

void PolicyEnforcer::LoadLolBinPatterns() {
    // Common LOLBins that can be abused
    m_lolBins = {
        L"powershell.exe", L"pwsh.exe", L"cmd.exe",
        L"certutil.exe", L"mshta.exe", L"rundll32.exe",
        L"regsvr32.exe", L"msiexec.exe", L"wmic.exe",
        L"cscript.exe", L"wscript.exe", L"bitsadmin.exe",
        L"msbuild.exe", L"installutil.exe", L"regasm.exe",
        L"regsvcs.exe", L"cmstp.exe", L"forfiles.exe"
    };
    
    // Suspicious patterns for each LOLBin
    m_lolBinPatterns = {
        {L"certutil.exe", {L"-urlcache", L"-decode", L"-encode", L"-split"}},
        {L"powershell.exe", {L"-enc", L"-encodedcommand", L"downloadstring", L"iex", L"invoke-expression", L"-nop", L"-w hidden"}},
        {L"mshta.exe", {L"javascript:", L"vbscript:", L"http://", L"https://"}},
        {L"rundll32.exe", {L"javascript:", L"shell32.dll,ShellExec_RunDLL"}},
        {L"regsvr32.exe", {L"/s", L"/n", L"/u", L"/i:http"}},
        {L"bitsadmin.exe", {L"/transfer", L"/create", L"/addfile"}},
        {L"wmic.exe", {L"process call create", L"/node:", L"/format:"}},
    };
}

PolicyEnforcer::ExecutionResult PolicyEnforcer::CheckExecution(const ProcessEvent& event) {
    // System processes always allowed
    if (IsSystemProcess(event.imagePath)) {
        return ExecutionResult::Allowed;
    }
    
    // Check whitelist
    if (Database::Instance().IsWhitelisted(event.hashSha256, event.signer, event.imagePath)) {
        return ExecutionResult::Allowed;
    }
    
    // Check session-allowed
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        if (m_sessionAllowed.count(event.hashSha256) > 0) {
            return ExecutionResult::Allowed;
        }
    }
    
    // Microsoft-signed binaries require scrutiny if they're LOLBins
    if (IsMicrosoftSigned(event.imagePath) && IsLolBin(event.imagePath)) {
        if (IsLolBinAbuse(event.imagePath, event.commandLine)) {
            return ExecutionResult::Blocked;
        }
        return ExecutionResult::Allowed;
    }
    
    // Microsoft-signed non-LOLBins are allowed
    if (IsMicrosoftSigned(event.imagePath)) {
        return ExecutionResult::Allowed;
    }
    
    // Everything else is blocked pending authorization
    return ExecutionResult::Blocked;
}

void PolicyEnforcer::ApplyDecision(uint64_t eventId, Decision decision, const ProcessEvent& event) {
    Database::Instance().UpdateProcessDecision(eventId, decision, L"User decision");
    
    if (decision == Decision::AllowPermanent) {
        WhitelistEntry entry;
        entry.entryType = L"hash";
        entry.value = event.hashSha256;
        entry.addedTimestamp = GetCurrentTimestamp();
        entry.notes = L"User approved: " + event.imagePath;
        Database::Instance().AddWhitelistEntry(entry);
    }
    else if (decision == Decision::AllowSession) {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        m_sessionAllowed.insert(event.hashSha256);
    }
}

bool PolicyEnforcer::IsLolBin(const std::wstring& imagePath) {
    std::wstring filename = imagePath;
    auto pos = filename.find_last_of(L"\\/");
    if (pos != std::wstring::npos) filename = filename.substr(pos + 1);
    
    std::transform(filename.begin(), filename.end(), filename.begin(), ::towlower);
    
    for (const auto& lolbin : m_lolBins) {
        if (filename == lolbin) return true;
    }
    return false;
}

bool PolicyEnforcer::IsLolBinAbuse(const std::wstring& imagePath, const std::wstring& commandLine) {
    std::wstring filename = imagePath;
    auto pos = filename.find_last_of(L"\\/");
    if (pos != std::wstring::npos) filename = filename.substr(pos + 1);
    std::transform(filename.begin(), filename.end(), filename.begin(), ::towlower);
    
    std::wstring cmdLower = commandLine;
    std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::towlower);
    
    for (const auto& pattern : m_lolBinPatterns) {
        if (filename == pattern.executable) {
            for (const auto& arg : pattern.suspiciousArgs) {
                if (cmdLower.find(arg) != std::wstring::npos) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool PolicyEnforcer::IsSystemProcess(const std::wstring& imagePath) {
    std::wstring pathLower = imagePath;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
    
    // System paths
    return pathLower.find(L"c:\\windows\\system32\\") == 0 ||
           pathLower.find(L"c:\\windows\\syswow64\\") == 0 ||
           pathLower.find(L"c:\\windows\\winsxs\\") == 0;
}

bool PolicyEnforcer::IsMicrosoftSigned(const std::wstring& imagePath) {
    // Verify digital signature using WinVerifyTrust
    WINTRUST_FILE_INFO fileData = {};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = imagePath.c_str();
    fileData.hFile = NULL;
    fileData.pgKnownSubject = NULL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.pPolicyCallbackData = NULL;
    winTrustData.pSIPClientData = NULL;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; // Offline mode - no revocation check
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = NULL;
    winTrustData.pwszURLReference = NULL;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;
    winTrustData.dwUIContext = 0;
    winTrustData.pFile = &fileData;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &winTrustData);
    
    // Clean up
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    if (status != ERROR_SUCCESS) {
        return false; // Not signed or signature invalid
    }

    // Now verify it's actually Microsoft-signed by checking the certificate
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD dwEncoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    
    BOOL bResult = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        imagePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &hStore,
        &hMsg,
        NULL
    );

    bool isMicrosoft = false;
    if (bResult && hStore) {
        PCCERT_CONTEXT pCertContext = NULL;
        while ((pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) != NULL) {
            wchar_t szName[256] = {0};
            
            CertGetNameStringW(
                pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                NULL,
                szName,
                256
            );
            
            std::wstring name(szName);
            // Check if issued by Microsoft
            if (name.find(L"Microsoft") != std::wstring::npos ||
                name.find(L"Windows") != std::wstring::npos) {
                isMicrosoft = true;
                CertFreeCertificateContext(pCertContext);
                break;
            }
        }
    }

    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);

    return isMicrosoft;
}
