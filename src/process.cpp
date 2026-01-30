#include "process.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <algorithm>
#include <cstring>

#ifdef __linux__
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <pwd.h>
#endif

// Constants
namespace {
    constexpr int DEFAULT_MIN_PID_FOR_EMPTY_CMD = 1000;
    
    // Known system process names
    const std::vector<std::string> SYSTEM_PROCESS_PREFIXES = {
        "kworker", "ksoftirqd", "rcu", "migration", "irq/",
        "idle_inject", "cpuhp", "kswapd", "watchdog", "jbd2",
        "scsi_eh", "btrfs", "kthreadd", "kdevtmpfs", "netns",
        "khungtaskd", "oom_reaper", "writeback", "kcompactd",
        "ksmd", "khugepaged", "crypto", "kintegrityd", "kblockd",
        "ata_sff", "md", "edac-poller", "devfreq_wq", "watchdogd",
        "iprt-VBoxTscThread", "krfcommd", "psimon"  // VirtualBox, Bluetooth, etc.
    };
}

#ifdef __linux__

// RAII wrapper for DIR*
class DirHandle {
public:
    explicit DirHandle(const char* path) : m_dir(opendir(path)) {
        if (!m_dir) {
            throw ProcessMonitorException(
                std::string("Failed to open directory: ") + path + 
                " - " + strerror(errno));
        }
    }
    
    ~DirHandle() {
        if (m_dir) {
            closedir(m_dir);
        }
    }
    
    // Disable copying
    DirHandle(const DirHandle&) = delete;
    DirHandle& operator=(const DirHandle&) = delete;
    
    DIR* get() { return m_dir; }
    
private:
    DIR* m_dir;
};

#endif

ProcessMonitor::ProcessMonitor() 
    : m_verbose(false)
    , m_minPidForEmptyCmdCheck(DEFAULT_MIN_PID_FOR_EMPTY_CMD)
    , m_enableWhitelist(true) {  // Enable whitelist by default
    loadDefaultWhitelists();
}

ProcessMonitor::~ProcessMonitor() = default;

void ProcessMonitor::loadDefaultWhitelists() {
    // Whitelist common legitimate process names
    m_whitelistedProcessNames.insert("steam");
    m_whitelistedProcessNames.insert("steamwebhelper");
    m_whitelistedProcessNames.insert("srt-logger");
    m_whitelistedProcessNames.insert("srt-bwrap");
    m_whitelistedProcessNames.insert("steam-runtime-l");
    m_whitelistedProcessNames.insert("cpptools");
    m_whitelistedProcessNames.insert("cpptools-srv");
    m_whitelistedProcessNames.insert("code");
    m_whitelistedProcessNames.insert("electron");
    m_whitelistedProcessNames.insert("chrome");
    m_whitelistedProcessNames.insert("firefox");
    m_whitelistedProcessNames.insert("Discord");
    m_whitelistedProcessNames.insert("slack");
    m_whitelistedProcessNames.insert("spotify");
    m_whitelistedProcessNames.insert("telegram-desktop");
    
    // VirtualBox processes
    m_whitelistedProcessNames.insert("VBoxClient");
    m_whitelistedProcessNames.insert("VBoxService");
    m_whitelistedProcessNames.insert("iprt-VBoxTscThread");
    
    // Bluetooth
    m_whitelistedProcessNames.insert("krfcommd");
    m_whitelistedProcessNames.insert("bluetoothd");
    
    // System monitoring
    m_whitelistedProcessNames.insert("psimon");
    
    // Whitelist path prefixes (directories that are safe)
    m_whitelistedPathPrefixes.insert("/.local/");
    m_whitelistedPathPrefixes.insert("/.vscode");
    m_whitelistedPathPrefixes.insert("/.config/");
    m_whitelistedPathPrefixes.insert("/.cache/");
    m_whitelistedPathPrefixes.insert("/snap/");
    m_whitelistedPathPrefixes.insert("/opt/");
    m_whitelistedPathPrefixes.insert("/usr/lib/");
    m_whitelistedPathPrefixes.insert("/usr/share/");
    m_whitelistedPathPrefixes.insert("/var/lib/");
    
    if (m_verbose) {
        std::cout << "Loaded " << m_whitelistedProcessNames.size() 
                  << " whitelisted process names and " 
                  << m_whitelistedPathPrefixes.size() 
                  << " whitelisted path prefixes" << std::endl;
    }
}

void ProcessMonitor::addWhitelistedPath(const std::string& path) {
    m_whitelistedPathPrefixes.insert(path);
}

void ProcessMonitor::addWhitelistedProcess(const std::string& name) {
    m_whitelistedProcessNames.insert(name);
}

void ProcessMonitor::clearWhitelists() {
    m_whitelistedPaths.clear();
    m_whitelistedProcessNames.clear();
    m_whitelistedPathPrefixes.clear();
}

bool ProcessMonitor::isWhitelistedName(const std::string& name) const {
    if (!m_enableWhitelist) {
        return false;
    }
    
    return m_whitelistedProcessNames.find(name) != m_whitelistedProcessNames.end();
}

bool ProcessMonitor::isWhitelistedPath(const std::string& path) const {
    if (!m_enableWhitelist) {
        return false;
    }
    
    if (path.empty() || path == "unknown") {
        return false;
    }
    
    // Check exact path matches
    if (m_whitelistedPaths.find(path) != m_whitelistedPaths.end()) {
        return true;
    }
    
    // Check path prefix matches
    for (const auto& prefix : m_whitelistedPathPrefixes) {
        if (path.find(prefix) != std::string::npos) {
            return true;
        }
    }
    
    // Check if it's in user's home directory with common app directories
    if (isInHomeDirectory(path)) {
        // Allow common application directories in home
        if (contains(path, "/.local/") || 
            contains(path, "/.vscode") ||
            contains(path, "/.config/") ||
            contains(path, "/.cache/") ||
            contains(path, "/snap/") ||
            contains(path, "/opt/")) {
            return true;
        }
    }
    
    return false;
}

bool ProcessMonitor::isWhitelisted(const Process& p) const {
    if (!m_enableWhitelist) {
        return false;
    }
    
    // Check if process name is whitelisted
    if (isWhitelistedName(p.name)) {
        if (m_verbose) {
            std::cout << "  [WHITELIST] Process name '" << p.name << "' is whitelisted" << std::endl;
        }
        return true;
    }
    
    // Check if path is whitelisted
    if (isWhitelistedPath(p.path)) {
        if (m_verbose) {
            std::cout << "  [WHITELIST] Path '" << p.path << "' is whitelisted" << std::endl;
        }
        return true;
    }
    
    return false;
}

bool ProcessMonitor::isSystemName(const std::string& name) const {
    for (const auto& prefix : SYSTEM_PROCESS_PREFIXES) {
        if (name.find(prefix) == 0) {
            return true;
        }
    }
    return false;
}

bool ProcessMonitor::isRealSystemProcess(const Process& p) const {
    // Real system/kernel processes have:
    // 1. System-like name
    // 2. UID 0 (root)
    // 3. No executable path (kernel threads)
    // 4. Empty command line
    return isSystemName(p.name) &&
           p.uid == 0 &&
           (p.path == "unknown" || p.path.empty()) &&
           p.cmdline.empty();
}

#ifdef __linux__

bool ProcessMonitor::readProcessName(int pid, std::string& name) const {
    std::ifstream comm("/proc/" + std::to_string(pid) + "/comm");
    if (!comm.is_open()) {
        return false;
    }
    
    if (!std::getline(comm, name)) {
        return false;
    }
    
    name = trim(name);
    return true;
}

bool ProcessMonitor::readProcessPath(int pid, std::string& path) const {
    char buf[PATH_MAX];
    std::string exePath = "/proc/" + std::to_string(pid) + "/exe";
    
    ssize_t len = readlink(exePath.c_str(), buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        path = std::string(buf, len);
        return true;
    }
    
    path = "unknown";
    return false;
}

bool ProcessMonitor::readProcessCmdline(int pid, std::string& cmdline) const {
    std::ifstream cmd("/proc/" + std::to_string(pid) + "/cmdline");
    if (!cmd.is_open()) {
        return false;
    }
    
    cmdline.clear();
    char c;
    while (cmd.get(c)) {
        if (c == '\0') {
            cmdline += ' ';
        } else {
            cmdline += c;
        }
    }
    
    cmdline = trim(cmdline);
    return true;
}

bool ProcessMonitor::readProcessState(int pid, std::string& state) const {
    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
    if (!status.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("State:", 0) == 0) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                state = trim(line.substr(pos + 1));
                return true;
            }
        }
    }
    
    return false;
}

bool ProcessMonitor::readProcessStartTime(int pid, unsigned long long& startTime) const {
    std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
    if (!stat.is_open()) {
        return false;
    }
    
    std::string line;
    if (!std::getline(stat, line)) {
        return false;
    }
    
    // The start time is the 22nd field in /proc/[pid]/stat
    // Format: pid (comm) state ... starttime ...
    size_t lastParen = line.rfind(')');
    if (lastParen == std::string::npos) {
        return false;
    }
    
    std::istringstream iss(line.substr(lastParen + 1));
    std::string field;
    for (int i = 0; i < 20; ++i) {
        if (!(iss >> field)) {
            return false;
        }
    }
    
    if (iss >> startTime) {
        return true;
    }
    
    return false;
}

std::optional<Process> ProcessMonitor::getProcessInfo(int pid) {
    if (pid <= 0) {
        return std::nullopt;
    }
    
    Process p;
    p.pid = pid;
    
    // Try to read all process information
    if (!readProcessName(pid, p.name)) {
        return std::nullopt;
    }
    
    readProcessPath(pid, p.path);
    readProcessCmdline(pid, p.cmdline);
    readProcessState(pid, p.state);
    readProcessStartTime(pid, p.startTime);
    
    // UID is important, fail if we can't get it
    if (!getProcessUID(pid, p.uid)) {
        if (m_verbose) {
            std::cerr << "Warning: Could not get UID for PID " << pid << std::endl;
        }
    }
    
    return p;
}

std::vector<Process> ProcessMonitor::listProcesses() {
    std::vector<Process> processes;
    
    try {
        DirHandle dir("/proc");
        struct dirent* entry;
        
        while ((entry = readdir(dir.get())) != nullptr) {
            // Check if directory name is numeric (PID)
            if (!isNumeric(entry->d_name)) {
                continue;
            }
            
            int pid = safeStringToInt(entry->d_name);
            if (pid <= 0) {
                continue;
            }
            
            // Try to get process info
            auto processOpt = getProcessInfo(pid);
            if (processOpt.has_value()) {
                processes.push_back(processOpt.value());
            } else if (m_verbose) {
                std::cerr << "Warning: Could not read info for PID " << pid << std::endl;
            }
        }
    } catch (const ProcessMonitorException& e) {
        if (m_verbose) {
            std::cerr << "Error listing processes: " << e.what() << std::endl;
        }
        throw;
    }
    
    return processes;
}

std::vector<Process> ProcessMonitor::analyzeSuspicious(
        const std::vector<Process>& procs) {
    
    std::vector<Process> suspicious;
    
    for (const auto& p : procs) {
        // Check whitelist first
        if (isWhitelisted(p)) {
            continue;
        }
        
        bool isSuspicious = false;
        std::string reason;
        
        // Check 1: Fake system process (has system name but not real system process)
        if (isSystemName(p.name) && !isRealSystemProcess(p)) {
            isSuspicious = true;
            reason = "Fake system process name";
            
            if (m_verbose) {
                std::cout << "[SUSPICIOUS] PID " << p.pid 
                          << " (" << p.name << "): " << reason << std::endl;
            }
        }
        
        // Check 2: Running from temporary directory (not in home)
        if (isTempPath(p.path) && !isInHomeDirectory(p.path)) {
            isSuspicious = true;
            reason = "Running from temporary directory";
            
            if (m_verbose) {
                std::cout << "[SUSPICIOUS] PID " << p.pid 
                          << " (" << p.name << "): " << reason << std::endl;
            }
        }
        
        // Check 3: Running from hidden directory (but not common app directories)
        if (isHiddenPath(p.path) && !isWhitelistedPath(p.path)) {
            isSuspicious = true;
            reason = "Running from hidden directory";
            
            if (m_verbose) {
                std::cout << "[SUSPICIOUS] PID " << p.pid 
                          << " (" << p.name << "): " << reason << std::endl;
            }
        }
        
        // Check 4: User process with empty command line (unusual)
        if (p.cmdline.empty() && 
            p.pid >= m_minPidForEmptyCmdCheck && 
            !isRealSystemProcess(p)) {
            isSuspicious = true;
            reason = "User process with empty command line";
            
            if (m_verbose) {
                std::cout << "[SUSPICIOUS] PID " << p.pid 
                          << " (" << p.name << "): " << reason << std::endl;
            }
        }
        
        // Check 5: Suspicious characters in name
        if (hasSuspiciousChars(p.name)) {
            isSuspicious = true;
            reason = "Suspicious characters in process name";
            
            if (m_verbose) {
                std::cout << "[SUSPICIOUS] PID " << p.pid 
                          << " (" << p.name << "): " << reason << std::endl;
            }
        }
        
        // Check 6: Executable path doesn't exist (deleted executable - common in malware)
        if (!p.path.empty() && p.path != "unknown" && !pathExists(p.path)) {
            // Check if it's a deleted file
            if (p.path.find("(deleted)") != std::string::npos) {
                isSuspicious = true;
                reason = "Running from deleted executable";
                
                if (m_verbose) {
                    std::cout << "[SUSPICIOUS] PID " << p.pid 
                              << " (" << p.name << "): " << reason << std::endl;
                }
            }
        }
        
        if (isSuspicious) {
            suspicious.push_back(p);
        }
    }
    
    return suspicious;
}

#else
// Non-Linux implementations (stubs for portability)

std::optional<Process> ProcessMonitor::getProcessInfo(int pid) {
    throw ProcessMonitorException("Process monitoring not supported on this platform");
}

std::vector<Process> ProcessMonitor::listProcesses() {
    throw ProcessMonitorException("Process monitoring not supported on this platform");
}

std::vector<Process> ProcessMonitor::analyzeSuspicious(
        const std::vector<Process>& procs) {
    throw ProcessMonitorException("Process monitoring not supported on this platform");
}

bool ProcessMonitor::readProcessName(int pid, std::string& name) const { return false; }
bool ProcessMonitor::readProcessPath(int pid, std::string& path) const { return false; }
bool ProcessMonitor::readProcessCmdline(int pid, std::string& cmdline) const { return false; }
bool ProcessMonitor::readProcessState(int pid, std::string& state) const { return false; }
bool ProcessMonitor::readProcessStartTime(int pid, unsigned long long& startTime) const { return false; }

#endif