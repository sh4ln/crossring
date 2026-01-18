// CROSSRING Linux - eBPF Process Monitor Implementation
#include "process_monitor.h"
#include "common.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <cstring>

// For audit subsystem (fallback)
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

namespace crossring {

ProcessMonitor::~ProcessMonitor() {
    stop();
}

ProcessMonitor& ProcessMonitor::instance() {
    static ProcessMonitor inst;
    return inst;
}

bool ProcessMonitor::ebpf_available() {
#ifdef USE_EBPF
    // Check kernel version >= 4.18 for modern eBPF
    struct utsname buf;
    if (uname(&buf) != 0) return false;
    
    int major, minor;
    if (sscanf(buf.release, "%d.%d", &major, &minor) != 2) return false;
    
    return (major > 4) || (major == 4 && minor >= 18);
#else
    return false;
#endif
}

bool ProcessMonitor::start(Callback callback) {
    if (running_.load()) return true;
    
    callback_ = std::move(callback);
    running_ = true;
    
#ifdef USE_EBPF
    if (ebpf_available()) {
        thread_ = std::make_unique<std::thread>(&ProcessMonitor::process_ebpf_events, this);
    } else {
        thread_ = std::make_unique<std::thread>(&ProcessMonitor::process_audit_events, this);
    }
#else
    thread_ = std::make_unique<std::thread>(&ProcessMonitor::process_audit_events, this);
#endif
    
    return true;
}

void ProcessMonitor::stop() {
    running_ = false;
    
    if (thread_ && thread_->joinable()) {
        thread_->join();
    }
    
#ifdef USE_EBPF
    if (bpf_obj_) {
        bpf_object__close(bpf_obj_);
        bpf_obj_ = nullptr;
    }
#endif
}

// Read process info from /proc
static ProcessEvent read_proc_info(pid_t pid) {
    ProcessEvent event;
    event.pid = pid;
    event.timestamp = get_current_timestamp();
    
    // Read exe path
    char path[PATH_MAX];
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
    ssize_t len = readlink(exe_link, path, sizeof(path) - 1);
    if (len > 0) {
        path[len] = '\0';
        event.exe_path = path;
        event.sha256 = compute_sha256(event.exe_path);
    }
    
    // Read cmdline
    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
    std::ifstream cmdfile(cmdline_path);
    if (cmdfile) {
        std::stringstream ss;
        char c;
        while (cmdfile.get(c)) {
            ss << (c == '\0' ? ' ' : c);
        }
        event.cmdline = ss.str();
    }
    
    // Read ppid from status
    char status_path[64];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    std::ifstream statusfile(status_path);
    if (statusfile) {
        std::string line;
        while (std::getline(statusfile, line)) {
            if (line.compare(0, 5, "PPid:") == 0) {
                event.ppid = std::stoi(line.substr(6));
            } else if (line.compare(0, 4, "Uid:") == 0) {
                event.uid = std::stoi(line.substr(5));
            } else if (line.compare(0, 4, "Gid:") == 0) {
                event.gid = std::stoi(line.substr(5));
            }
        }
    }
    
    event.username = get_username(event.uid);
    
    return event;
}

void ProcessMonitor::process_audit_events() {
    // Use proc connector for process events (requires root)
    int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (sock < 0) {
        // Fallback to polling /proc
        monitor_thread();
        return;
    }
    
    struct sockaddr_nl addr = {};
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = CN_IDX_PROC;
    addr.nl_pid = getpid();
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        monitor_thread();
        return;
    }
    
    // Subscribe to proc events
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__((__packed__)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } msg = {};
    
    msg.nl_hdr.nlmsg_len = sizeof(msg);
    msg.nl_hdr.nlmsg_pid = getpid();
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;
    msg.cn_msg.id.idx = CN_IDX_PROC;
    msg.cn_msg.id.val = CN_VAL_PROC;
    msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);
    msg.cn_mcast = PROC_CN_MCAST_LISTEN;
    
    if (send(sock, &msg, sizeof(msg), 0) < 0) {
        close(sock);
        monitor_thread();
        return;
    }
    
    // Receive events
    char buf[4096];
    while (running_.load()) {
        struct sockaddr_nl from_addr;
        socklen_t from_len = sizeof(from_addr);
        
        ssize_t len = recvfrom(sock, buf, sizeof(buf), 0,
                               (struct sockaddr*)&from_addr, &from_len);
        
        if (len <= 0) continue;
        
        struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
        if (!NLMSG_OK(nlh, len)) continue;
        
        struct cn_msg* cn = (struct cn_msg*)NLMSG_DATA(nlh);
        struct proc_event* ev = (struct proc_event*)cn->data;
        
        if (ev->what == PROC_EVENT_EXEC) {
            pid_t pid = ev->event_data.exec.process_pid;
            
            if (callback_) {
                ProcessEvent event = read_proc_info(pid);
                callback_(event);
            }
        }
    }
    
    // Unsubscribe
    msg.cn_mcast = PROC_CN_MCAST_IGNORE;
    send(sock, &msg, sizeof(msg), 0);
    close(sock);
}

void ProcessMonitor::monitor_thread() {
    // Fallback: poll /proc for new processes
    std::unordered_map<pid_t, bool> known_pids;
    
    while (running_.load()) {
        DIR* proc = opendir("/proc");
        if (!proc) {
            sleep(1);
            continue;
        }
        
        std::unordered_map<pid_t, bool> current_pids;
        
        struct dirent* entry;
        while ((entry = readdir(proc)) != nullptr) {
            if (entry->d_type != DT_DIR) continue;
            
            char* end;
            pid_t pid = strtol(entry->d_name, &end, 10);
            if (*end != '\0' || pid <= 0) continue;
            
            current_pids[pid] = true;
            
            // New process detected
            if (known_pids.find(pid) == known_pids.end()) {
                if (callback_) {
                    ProcessEvent event = read_proc_info(pid);
                    callback_(event);
                }
            }
        }
        
        closedir(proc);
        known_pids = std::move(current_pids);
        
        usleep(500000);  // 500ms poll interval
    }
}

#ifdef USE_EBPF
void ProcessMonitor::process_ebpf_events() {
    // Load eBPF program
    // In production, this would load a compiled BPF program
    
    // For now, fall back to audit events
    process_audit_events();
}
#endif

} // namespace crossring
