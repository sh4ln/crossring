// CROSSRING Linux - Persistence Monitor
#include "common.h"

#include <fstream>
#include <sstream>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <pwd.h>

namespace crossring {

class PersistenceMonitor {
public:
    using Callback = std::function<void(const PersistenceEntry&)>;
    
    static PersistenceMonitor& instance() {
        static PersistenceMonitor inst;
        return inst;
    }
    
    bool start(Callback callback) {
        callback_ = std::move(callback);
        running_ = true;
        
        // Initialize inotify
        inotify_fd_ = inotify_init1(IN_NONBLOCK);
        if (inotify_fd_ < 0) return false;
        
        // Add watches for persistence locations
        add_watch("/etc/cron.d");
        add_watch("/etc/systemd/system");
        add_watch("/etc/init.d");
        add_watch("/etc/profile.d");
        
        // User-specific paths
        const char* home = getenv("HOME");
        if (home) {
            add_watch(std::string(home) + "/.bashrc");
            add_watch(std::string(home) + "/.profile");
            add_watch(std::string(home) + "/.config/autostart");
        }
        
        thread_ = std::make_unique<std::thread>(&PersistenceMonitor::monitor_loop, this);
        return true;
    }
    
    void stop() {
        running_ = false;
        if (thread_ && thread_->joinable()) {
            thread_->join();
        }
        
        for (auto& [wd, path] : watch_paths_) {
            inotify_rm_watch(inotify_fd_, wd);
        }
        
        if (inotify_fd_ >= 0) {
            close(inotify_fd_);
            inotify_fd_ = -1;
        }
    }
    
    std::vector<PersistenceEntry> get_current_entries() {
        std::vector<PersistenceEntry> entries;
        
        // Scan cron
        scan_directory("/etc/cron.d", "cron", entries);
        scan_directory("/etc/cron.daily", "cron", entries);
        
        // Scan systemd
        scan_directory("/etc/systemd/system", "systemd", entries);
        
        // Scan init.d
        scan_directory("/etc/init.d", "init", entries);
        
        // Scan user startup
        const char* home = getenv("HOME");
        if (home) {
            scan_file(std::string(home) + "/.bashrc", "shell", entries);
            scan_file(std::string(home) + "/.profile", "shell", entries);
        }
        
        return entries;
    }
    
private:
    void add_watch(const std::string& path) {
        struct stat st;
        if (stat(path.c_str(), &st) != 0) return;
        
        int wd = inotify_add_watch(inotify_fd_, path.c_str(),
                                    IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_TO);
        if (wd >= 0) {
            watch_paths_[wd] = path;
        }
    }
    
    void monitor_loop() {
        char buffer[4096];
        
        while (running_.load()) {
            ssize_t len = read(inotify_fd_, buffer, sizeof(buffer));
            if (len <= 0) {
                usleep(500000);  // 500ms
                continue;
            }
            
            for (char* ptr = buffer; ptr < buffer + len; ) {
                auto* event = reinterpret_cast<inotify_event*>(ptr);
                
                if (event->len > 0 && callback_) {
                    auto it = watch_paths_.find(event->wd);
                    if (it != watch_paths_.end()) {
                        PersistenceEntry entry;
                        entry.location = it->second + "/" + event->name;
                        entry.timestamp = get_current_timestamp();
                        entry.is_new = (event->mask & (IN_CREATE | IN_MOVED_TO)) != 0;
                        
                        // Determine type
                        if (it->second.find("cron") != std::string::npos) {
                            entry.type = "cron";
                        } else if (it->second.find("systemd") != std::string::npos) {
                            entry.type = "systemd";
                        } else if (it->second.find("init.d") != std::string::npos) {
                            entry.type = "init";
                        } else {
                            entry.type = "shell";
                        }
                        
                        callback_(entry);
                    }
                }
                
                ptr += sizeof(inotify_event) + event->len;
            }
        }
    }
    
    void scan_directory(const std::string& path, const std::string& type,
                        std::vector<PersistenceEntry>& entries) {
        DIR* dir = opendir(path.c_str());
        if (!dir) return;
        
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;
            
            PersistenceEntry pe;
            pe.type = type;
            pe.location = path + "/" + entry->d_name;
            pe.timestamp = get_current_timestamp();
            entries.push_back(pe);
        }
        
        closedir(dir);
    }
    
    void scan_file(const std::string& path, const std::string& type,
                   std::vector<PersistenceEntry>& entries) {
        struct stat st;
        if (stat(path.c_str(), &st) == 0) {
            PersistenceEntry pe;
            pe.type = type;
            pe.location = path;
            pe.timestamp = get_current_timestamp();
            entries.push_back(pe);
        }
    }
    
    Callback callback_;
    std::atomic<bool> running_{false};
    std::unique_ptr<std::thread> thread_;
    int inotify_fd_ = -1;
    std::unordered_map<int, std::string> watch_paths_;
};

} // namespace crossring
