#pragma once

#include "common.h"

#ifdef USE_EBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#endif

namespace crossring {

// Process monitor using eBPF (modern) or audit (fallback)
class ProcessMonitor {
public:
    using Callback = std::function<void(const ProcessEvent&)>;
    
    static ProcessMonitor& instance();
    
    bool start(Callback callback);
    void stop();
    bool is_running() const { return running_.load(); }
    
    // Check if eBPF is available
    static bool ebpf_available();
    
private:
    ProcessMonitor() = default;
    ~ProcessMonitor();
    
    void monitor_thread();
    void process_ebpf_events();
    void process_audit_events();
    
    Callback callback_;
    std::atomic<bool> running_{false};
    std::unique_ptr<std::thread> thread_;
    
#ifdef USE_EBPF
    struct bpf_object* bpf_obj_ = nullptr;
    int perf_fd_ = -1;
#endif
};

// eBPF program for process monitoring
#ifdef USE_EBPF
// This would be in a separate .bpf.c file compiled with clang
/*
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter* ctx) {
    struct event {
        u32 pid;
        u32 ppid;
        u32 uid;
        char filename[256];
    } e = {};
    
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid();
    
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    e.ppid = BPF_CORE_READ(task, real_parent, pid);
    
    bpf_probe_read_user_str(e.filename, sizeof(e.filename), 
                            (const char*)ctx->args[0]);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
*/
#endif

} // namespace crossring
