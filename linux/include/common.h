#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <mutex>

// CROSSRING Linux Common Types

namespace crossring {

struct ProcessEvent {
    std::string timestamp;
    pid_t pid;
    pid_t ppid;
    std::string exe_path;
    std::string cmdline;
    std::string sha256;
    uid_t uid;
    gid_t gid;
    std::string username;
};

struct NetworkEvent {
    std::string timestamp;
    pid_t pid;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::string protocol;
};

struct PersistenceEntry {
    std::string type;       // "cron", "systemd", "bashrc", "profile"
    std::string location;
    std::string value;
    std::string timestamp;
    bool is_new;
};

enum class Decision {
    Allow,
    Deny,
    Pending
};

enum class TrustLevel {
    Untrusted = 0,
    LowTrust = 1,
    MediumTrust = 2,
    HighTrust = 3,
    SystemTrust = 4
};

// Utility functions
std::string get_current_timestamp();
std::string compute_sha256(const std::string& file_path);
std::string get_username(uid_t uid);

// Configuration
struct Config {
    bool enable_network_monitor = true;
    bool enable_persistence_monitor = true;
    bool block_usb_execution = true;
    int event_retention_days = 90;
    std::string db_path = "/var/lib/crossring/database.db";
    std::string socket_path = "/run/crossring.sock";
};

} // namespace crossring
