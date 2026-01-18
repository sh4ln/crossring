#pragma once

#include "common.h"
#include <fstream>

namespace crossring {

// AppArmor policy generator for application whitelisting
class AppArmorPolicy {
public:
    static AppArmorPolicy& instance();
    
    bool initialize();
    void shutdown();
    
    // Generate profile for an allowed application
    bool generate_profile(const std::string& exe_path, 
                         const std::vector<std::string>& allowed_paths = {});
    
    // Load/unload profiles
    bool load_profile(const std::string& profile_name);
    bool unload_profile(const std::string& profile_name);
    
    // Enforcement modes
    bool set_enforce_mode(const std::string& profile_name);
    bool set_complain_mode(const std::string& profile_name);
    
    // Check if AppArmor is available
    static bool is_available();
    
    // Get list of managed profiles
    std::vector<std::string> get_managed_profiles();
    
private:
    AppArmorPolicy() = default;
    
    std::string generate_profile_content(const std::string& exe_path,
                                         const std::vector<std::string>& allowed_paths);
    bool write_profile(const std::string& name, const std::string& content);
    bool run_apparmor_parser(const std::string& args);
    
    static constexpr const char* PROFILE_DIR = "/etc/apparmor.d/crossring/";
    static constexpr const char* APPARMOR_PARSER = "/sbin/apparmor_parser";
    
    std::vector<std::string> managed_profiles_;
    std::mutex mutex_;
};

/*
Example generated profile:

#include <tunables/global>

profile crossring_myapp /usr/bin/myapp {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    
    # Allow reading self
    /usr/bin/myapp mr,
    
    # Allow reading libraries
    /lib/** rm,
    /usr/lib/** rm,
    
    # Allow reading config
    /etc/myapp/* r,
    
    # Deny sensitive files
    deny /etc/shadow r,
    deny /etc/passwd w,
    deny /root/** rwx,
    
    # Network (optional)
    # network inet stream,
    # network inet dgram,
}
*/

} // namespace crossring
