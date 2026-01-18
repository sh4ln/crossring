// CROSSRING Linux - AppArmor Policy Generator
#include "apparmor_policy.h"
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>

namespace crossring {

// Helper: Validate input to prevent command injection
static bool validate_path(const std::string& path) {
    // Reject paths with shell metacharacters
    if (path.find("..") != std::string::npos ||
        path.find(";") != std::string::npos ||
        path.find("&") != std::string::npos ||
        path.find("|") != std::string::npos ||
        path.find("`") != std::string::npos ||
        path.find("$") != std::string::npos ||
        path.find("'") != std::string::npos ||
        path.find("\"") != std::string::npos) {
        return false;
    }
    return true;
}

static bool validate_profile_name(const std::string& name) {
    // Profile names should be alphanumeric with underscores only
    for (char c : name) {
        if (!isalnum(c) && c != '_' && c != '-') {
            return false;
        }
    }
    return !name.empty();
}

// Helper: Execute command using fork/exec instead of system()
static bool execute_command(const std::string& program, const std::vector<std::string>& args) {
    pid_t pid = fork();
    if (pid == -1) {
        return false; // Fork failed
    }
    
    if (pid == 0) {
        // Child process - redirect stderr to /dev/null
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        
        // Build argv array
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(program.c_str()));
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);
        
        execv(program.c_str(), argv.data());
        _exit(1); // If exec fails
    }
    
    // Parent process - wait for child
    int status;
    waitpid(pid, &status, 0);
    
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

AppArmorPolicy& AppArmorPolicy::instance() {
    static AppArmorPolicy inst;
    return inst;
}

bool AppArmorPolicy::is_available() {
    struct stat st;
    return stat("/sys/kernel/security/apparmor", &st) == 0;
}

bool AppArmorPolicy::initialize() {
    if (!is_available()) return false;
    
    // Create profile directory
    mkdir(PROFILE_DIR, 0755);
    
    return true;
}

void AppArmorPolicy::shutdown() {
    // Unload all managed profiles
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& profile : managed_profiles_) {
        unload_profile(profile);
    }
    managed_profiles_.clear();
}

std::string AppArmorPolicy::generate_profile_content(
    const std::string& exe_path,
    const std::vector<std::string>& allowed_paths) {
    
    std::stringstream ss;
    
    // Extract profile name from path
    std::string name = exe_path;
    for (char& c : name) {
        if (c == '/' || c == '.') c = '_';
    }
    
    ss << "#include <tunables/global>\n\n";
    ss << "profile crossring_" << name << " " << exe_path << " {\n";
    ss << "    #include <abstractions/base>\n";
    ss << "    #include <abstractions/nameservice>\n\n";
    
    // Allow reading self
    ss << "    # Allow executing self\n";
    ss << "    " << exe_path << " mr,\n\n";
    
    // Allow reading libraries
    ss << "    # Allow shared libraries\n";
    ss << "    /lib/** rm,\n";
    ss << "    /lib64/** rm,\n";
    ss << "    /usr/lib/** rm,\n";
    ss << "    /usr/lib64/** rm,\n\n";
    
    // Custom allowed paths
    if (!allowed_paths.empty()) {
        ss << "    # Custom allowed paths\n";
        for (const auto& path : allowed_paths) {
            ss << "    " << path << " r,\n";
        }
        ss << "\n";
    }
    
    // Deny sensitive files
    ss << "    # Deny sensitive files\n";
    ss << "    deny /etc/shadow r,\n";
    ss << "    deny /etc/gshadow r,\n";
    ss << "    deny /root/** rwx,\n";
    ss << "    deny /etc/sudoers r,\n";
    ss << "    deny /etc/sudoers.d/** r,\n\n";
    
    // Deny persistence locations (CROSSRING enforces these)
    ss << "    # Deny persistence locations\n";
    ss << "    deny /etc/cron.d/** w,\n";
    ss << "    deny /etc/systemd/system/** w,\n";
    ss << "    deny ~/.bashrc w,\n";
    ss << "    deny ~/.profile w,\n\n";
    
    ss << "}\n";
    
    return ss.str();
}

bool AppArmorPolicy::write_profile(const std::string& name, const std::string& content) {
    if (!validate_profile_name(name)) return false;
    
    std::string path = std::string(PROFILE_DIR) + name;
    
    std::ofstream file(path);
    if (!file) return false;
    
    file << content;
    file.close();
    
    return true;
}

bool AppArmorPolicy::run_apparmor_parser(const std::string& option, const std::string& path) {
    // Validate path before execution
    if (!validate_path(path)) return false;
    
    return execute_command(APPARMOR_PARSER, {option, path});
}

bool AppArmorPolicy::generate_profile(const std::string& exe_path,
                                       const std::vector<std::string>& allowed_paths) {
    if (!validate_path(exe_path)) return false;
    
    std::string content = generate_profile_content(exe_path, allowed_paths);
    
    // Create profile name
    std::string name = exe_path;
    for (char& c : name) {
        if (c == '/' || c == '.') c = '_';
    }
    name = "crossring_" + name;
    
    if (!write_profile(name, content)) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    managed_profiles_.push_back(name);
    
    return true;
}

bool AppArmorPolicy::load_profile(const std::string& profile_name) {
    if (!validate_profile_name(profile_name)) return false;
    
    std::string path = std::string(PROFILE_DIR) + profile_name;
    return run_apparmor_parser("-r", path);
}

bool AppArmorPolicy::unload_profile(const std::string& profile_name) {
    if (!validate_profile_name(profile_name)) return false;
    
    std::string path = std::string(PROFILE_DIR) + profile_name;
    return run_apparmor_parser("-R", path);
}

bool AppArmorPolicy::set_enforce_mode(const std::string& profile_name) {
    if (!validate_profile_name(profile_name)) return false;
    
    return execute_command("/usr/sbin/aa-enforce", {profile_name});
}

bool AppArmorPolicy::set_complain_mode(const std::string& profile_name) {
    if (!validate_profile_name(profile_name)) return false;
    
    return execute_command("/usr/sbin/aa-complain", {profile_name});
}

std::vector<std::string> AppArmorPolicy::get_managed_profiles() {
    std::lock_guard<std::mutex> lock(mutex_);
    return managed_profiles_;
}

} // namespace crossring

