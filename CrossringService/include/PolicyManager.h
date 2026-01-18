#pragma once
#include "Common.h"

class AppLockerPolicy {
public:
    static AppLockerPolicy& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // Policy management
    bool GenerateDefaultDenyPolicy();
    bool ApplyPolicy();
    bool RemovePolicy();
    
    // Rule management
    bool AddPublisherRule(const std::wstring& publisherName, bool allow = true);
    bool AddHashRule(const std::wstring& hash, bool allow = true);
    bool AddPathRule(const std::wstring& path, bool allow = true);
    bool RemoveRule(const std::wstring& ruleId);
    
    // Query
    struct Rule {
        std::wstring id;
        std::wstring type;      // "Publisher", "Hash", "Path"
        std::wstring value;
        bool allow;
    };
    
    std::vector<Rule> GetCurrentRules();
    bool IsAppLockerEnabled();
    
private:
    AppLockerPolicy() = default;
    
    std::wstring GenerateXmlPolicy();
    bool ApplyXmlPolicy(const std::wstring& xml);
    
    std::vector<Rule> m_rules;
    std::mutex m_mutex;
};

class WdacPolicy {
public:
    static WdacPolicy& Instance();
    
    bool Initialize();
    
    // WDAC uses binary policy files
    bool GeneratePolicy(const std::wstring& outputPath);
    bool DeployPolicy(const std::wstring& policyPath);
    bool RemovePolicy();
    
    // Rule types
    bool AddAllowPublisher(const std::wstring& publisherInfo);
    bool AddAllowHash(const std::wstring& sha256);
    bool AddDenyHash(const std::wstring& sha256);
    
    // Audit mode
    bool EnableAuditMode();
    bool EnableEnforceMode();
    
private:
    WdacPolicy() = default;
    
    std::wstring m_policyGuid;
    bool m_auditMode = true;
};
