// CROSSRING Linux Security Core Implementation
#include "common.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/inotify.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace crossring {
namespace security {

// ============================================
// Task 1: Self-Immunity with Symlink Protection
// ============================================

class SelfProtection {
public:
    static SelfProtection& instance() {
        static SelfProtection inst;
        return inst;
    }
    
    bool initialize(const std::string& install_dir) {
        install_dir_ = install_dir;
        protected_binaries_.clear();
        
        std::vector<std::string> names = {
            "crossring-daemon",
            "crossring-gui",
            "crossring-updater"
        };
        
        for (const auto& name : names) {
            std::string path = install_dir + "/" + name;
            
            struct stat st;
            if (stat(path.c_str(), &st) == 0) {
                ProtectedBinary pb;
                pb.canonical_path = resolve_real_path(path);
                pb.sha256_hash = compute_sha256(path);
                protected_binaries_.push_back(pb);
            }
        }
        
        return !protected_binaries_.empty();
    }
    
    bool is_protected_binary(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::string canonical = resolve_real_path(path);
        
        for (const auto& pb : protected_binaries_) {
            if (canonical == pb.canonical_path) {
                // Verify hash matches
                std::string current_hash = compute_sha256(path);
                if (current_hash == pb.sha256_hash) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
private:
    std::string resolve_real_path(const std::string& path) {
        char resolved[PATH_MAX];
        if (realpath(path.c_str(), resolved) == nullptr) {
            return path;
        }
        return std::string(resolved);
    }
    
    struct ProtectedBinary {
        std::string canonical_path;
        std::string sha256_hash;
    };
    
    std::vector<ProtectedBinary> protected_binaries_;
    std::string install_dir_;
    std::mutex mutex_;
};

// ============================================
// Task 4: Privilege Detection
// ============================================

class PrivilegeChecker {
public:
    enum class Level {
        Full,
        Limited,
        Minimal
    };
    
    struct Capabilities {
        bool can_terminate;
        bool can_quarantine;
        bool can_filter_network;
        bool can_modify_config;
    };
    
    static Level get_current_level() {
        auto caps = get_capabilities();
        
        if (caps.can_terminate && caps.can_quarantine && caps.can_filter_network) {
            return Level::Full;
        } else if (caps.can_terminate || caps.can_quarantine) {
            return Level::Limited;
        }
        
        return Level::Minimal;
    }
    
    static Capabilities get_capabilities() {
        Capabilities caps = {};
        
        caps.can_terminate = (geteuid() == 0);
        caps.can_quarantine = (geteuid() == 0);
        caps.can_filter_network = has_cap_net_admin();
        caps.can_modify_config = (geteuid() == 0);
        
        return caps;
    }
    
    static bool has_cap_net_admin() {
        cap_t caps = cap_get_proc();
        if (!caps) return false;
        
        cap_flag_value_t value;
        bool has = (cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &value) == 0 && 
                    value == CAP_SET);
        
        cap_free(caps);
        return has;
    }
    
    static bool restart_elevated() {
        char path[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
        if (len > 0) {
            path[len] = '\0';
            execlp("pkexec", "pkexec", path, nullptr);
        }
        return false;
    }
};

// ============================================
// Task 7: Smart Kill Loop
// ============================================

class ProcessTerminator {
public:
    enum class Result {
        Success,
        GracefulExit,
        ForcedKill,
        Failed,
        PossibleRootkit
    };
    
    static Result terminate(pid_t pid, bool use_kernel_fallback = true) {
        // Step 1: Graceful SIGTERM
        if (kill(pid, SIGTERM) == 0) {
            // Step 2: Wait 5 seconds
            for (int i = 0; i < 50; i++) {
                if (!is_running(pid)) {
                    return Result::GracefulExit;
                }
                usleep(100000);  // 100ms
            }
        }
        
        // Step 3: Forced SIGKILL
        if (kill(pid, SIGKILL) == 0) {
            usleep(500000);  // 500ms
            if (!is_running(pid)) {
                return Result::ForcedKill;
            }
        }
        
        // Step 4: Kernel-level (cgroup kill)
        if (use_kernel_fallback) {
            if (cgroup_kill(pid)) {
                usleep(500000);
                if (!is_running(pid)) {
                    return Result::Success;
                }
            }
            
            // Process survived kernel kill - rootkit?
            return Result::PossibleRootkit;
        }
        
        return Result::Failed;
    }
    
private:
    static bool is_running(pid_t pid) {
        return kill(pid, 0) == 0;
    }
    
    static bool cgroup_kill(pid_t pid) {
        char path[256];
        snprintf(path, sizeof(path), "/sys/fs/cgroup/pids/crossring/%d", pid);
        
        // Try to kill via cgroup
        std::string tasks_path = std::string(path) + "/cgroup.procs";
        std::ofstream f(tasks_path);
        if (f) {
            f << pid;
            return true;
        }
        return false;
    }
};

// ============================================
// Task 8: OS-Aware Integrity
// ============================================

class OSIntegrity {
public:
    struct Status {
        bool selinux_enforcing;
        bool apparmor_enabled;
        
        enum class Level { Green, Yellow, Orange, Red } overall;
        std::vector<std::string> warnings;
    };
    
    static Status check_system() {
        Status status = {};
        
        status.selinux_enforcing = is_selinux_enforcing();
        status.apparmor_enabled = is_apparmor_enabled();
        
        if (!status.selinux_enforcing && !status.apparmor_enabled) {
            status.overall = Status::Level::Orange;
            status.warnings.push_back("No MAC (SELinux/AppArmor) detected");
        } else {
            status.overall = Status::Level::Green;
        }
        
        return status;
    }
    
    static bool is_selinux_enforcing() {
        std::ifstream f("/sys/fs/selinux/enforce");
        if (!f) return false;
        
        int value = 0;
        f >> value;
        return value == 1;
    }
    
    static bool is_apparmor_enabled() {
        struct stat st;
        return stat("/sys/kernel/security/apparmor", &st) == 0;
    }
    
    static std::vector<std::string> get_recommendations() {
        std::vector<std::string> recs;
        auto status = check_system();
        
        if (!status.selinux_enforcing && !status.apparmor_enabled) {
            recs.push_back("Enable SELinux or AppArmor for Mandatory Access Control");
        }
        
        return recs;
    }
};

// ============================================
// Task 6: Configuration Manager
// ============================================

class ConfigManager {
public:
    enum class Mode {
        Monitoring,
        Balanced,
        ZeroTrust
    };
    
    static ConfigManager& instance() {
        static ConfigManager inst;
        return inst;
    }
    
    bool initialize() {
        if (is_first_run()) {
            return true;  // Will be configured via setup
        }
        
        if (!load_config()) return false;
        if (!verify_integrity()) return false;
        
        check_mode_expiry();
        return true;
    }
    
    bool is_first_run() {
        struct stat st;
        return stat("/etc/crossring/config.xml", &st) != 0;
    }
    
    Mode get_mode() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return mode_;
    }
    
    bool setup_first_run(Mode initial_mode) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        mode_ = initial_mode;
        install_date_ = time(nullptr);
        sequence_ = 1;
        
        if (initial_mode == Mode::Monitoring) {
            mode_locked_until_ = install_date_ + (7 * 24 * 60 * 60);  // 7 days
        }
        
        return save_config();
    }
    
private:
    bool load_config() {
        // TODO: Parse XML
        return true;
    }
    
    bool save_config() {
        // TODO: Write XML with HMAC
        return true;
    }
    
    bool verify_integrity() {
        // TODO: Verify HMAC signature
        return true;
    }
    
    void check_mode_expiry() {
        if (mode_ == Mode::Monitoring && time(nullptr) >= mode_locked_until_) {
            mode_ = Mode::Balanced;
            sequence_++;
            save_config();
            
            // Set immutable flag using ioctl instead of shell command
            int fd = open("/etc/crossring/config.xml", O_RDONLY);
            if (fd >= 0) {
                int flags = 0;
                if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0) {
                    flags |= FS_IMMUTABLE_FL;
                    ioctl(fd, FS_IOC_SETFLAGS, &flags);
                }
                close(fd);
            }
        }
    }
    
    Mode mode_ = Mode::Balanced;
    time_t install_date_ = 0;
    time_t mode_locked_until_ = 0;
    int sequence_ = 0;
    mutable std::mutex mutex_;
};

} // namespace security
} // namespace crossring
