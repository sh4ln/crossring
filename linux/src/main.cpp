// CROSSRING Linux Daemon - Main Entry Point
#include "common.h"
#include "process_monitor.h"
#include "apparmor_policy.h"

#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>
#include <getopt.h>
#include <iostream>

using namespace crossring;

static std::atomic<bool> g_running{true};

void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        g_running = false;
    }
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    
    if (setsid() < 0) exit(EXIT_FAILURE);
    
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    
    umask(0);
    chdir("/");
    
    for (int fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
        close(fd);
    }
    
    openlog("crossring", LOG_PID, LOG_DAEMON);
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n"
              << "  -d, --daemon      Run as daemon\n"
              << "  -c, --config FILE Configuration file\n"
              << "  -v, --verbose     Verbose output\n"
              << "  -h, --help        Show this help\n";
}

int main(int argc, char* argv[]) {
    bool daemon_mode = false;
    bool verbose = false;
    std::string config_file = "/etc/crossring/config.json";
    
    static struct option long_options[] = {
        {"daemon",  no_argument,       0, 'd'},
        {"config",  required_argument, 0, 'c'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "dc:vh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'd': daemon_mode = true; break;
            case 'c': config_file = optarg; break;
            case 'v': verbose = true; break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }
    
    // Check root
    if (geteuid() != 0) {
        std::cerr << "CROSSRING must run as root\n";
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    if (daemon_mode) {
        daemonize();
        syslog(LOG_INFO, "CROSSRING daemon started");
    } else {
        std::cout << "CROSSRING starting in console mode...\n";
    }
    
    // Initialize components
    if (AppArmorPolicy::is_available()) {
        AppArmorPolicy::instance().initialize();
        syslog(LOG_INFO, "AppArmor integration enabled");
    }
    
    // Start process monitor
    ProcessMonitor::instance().start([&](const ProcessEvent& event) {
        if (verbose && !daemon_mode) {
            std::cout << "[EXEC] " << event.exe_path 
                      << " (PID: " << event.pid << ")\n";
        }
        syslog(LOG_INFO, "Process: %s PID: %d", 
               event.exe_path.c_str(), event.pid);
        
        // TODO: Apply Zero Trust evaluation
        // TODO: Store in database
        // TODO: Send to GUI via Unix socket
    });
    
    // Main loop
    while (g_running.load()) {
        sleep(1);
    }
    
    // Cleanup
    ProcessMonitor::instance().stop();
    AppArmorPolicy::instance().shutdown();
    
    if (daemon_mode) {
        syslog(LOG_INFO, "CROSSRING daemon stopped");
        closelog();
    } else {
        std::cout << "CROSSRING stopped\n";
    }
    
    return 0;
}
