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

std::vector<std::string> ProcessMonitor::getDefaultConfigPaths() const {
    std::vector<std::string> paths;
    
    // Check user config first (highest priority)
    std::string homeDir = getHomeDirectory();
    if (!homeDir.empty()) {
        paths.push_back(homeDir + "/.config/procmon/default-whitelist.conf");
        paths.push_back(homeDir + "/.procmon/default-whitelist.conf");
    }
    
    // Then system-wide configs
    paths.push_back("/etc/procmon/default-whitelist.conf");
    paths.push_back("/usr/local/etc/procmon/default-whitelist.conf");
    
    // Check current directory (for development/testing)
    paths.push_back("./default-whitelist.conf");
    paths.push_back("../default-whitelist.conf");
    
    return paths;
}

bool ProcessMonitor::loadDefaultConfigFile() {
    auto configPaths = getDefaultConfigPaths();
    
    for (const auto& configPath : configPaths) {
        if (pathExists(configPath)) {
            if (m_verbose) {
                std::cout << "Loading default configuration from: " << configPath << std::endl;
            }
            
            if (loadWhitelistFromFile(configPath)) {
                if (m_verbose) {
                    std::cout << "Successfully loaded default configuration" << std::endl;
                }
                return true;
            }
        }
    }
    
    if (m_verbose) {
        std::cout << "No default configuration file found in standard locations:" << std::endl;
        for (const auto& path : configPaths) {
            std::cout << "  - " << path << std::endl;
        }
        std::cout << "Using hardcoded defaults..." << std::endl;
    }
    
    return false;
}

void ProcessMonitor::loadHardcodedDefaults() {
    // FALLBACK: Hardcoded whitelists if no config file is found
    // This ensures the tool works out-of-the-box without configuration
    
    if (m_verbose) {
        std::cout << "Loading hardcoded default whitelists..." << std::endl;
    }
    
    // Steam processes - must be in legitimate Steam directories
    addWhitelistedProcessWithPath("steam", "/.local/share/Steam/");
    addWhitelistedProcessWithPath("steam", "/.steam/");
    addWhitelistedProcessWithPath("steamwebhelper", "/.local/share/Steam/");
    addWhitelistedProcessWithPath("steamwebhelper", "/.steam/");
    addWhitelistedProcessWithPath("srt-logger", "/.local/share/Steam/");
    addWhitelistedProcessWithPath("srt-bwrap", "/.local/share/Steam/");
    addWhitelistedProcessWithPath("steam-runtime-l", "/.local/share/Steam/");
    
    // VS Code processes
    addWhitelistedProcessWithPath("cpptools", "/.vscode/");
    addWhitelistedProcessWithPath("cpptools-srv", "/.vscode/");
    addWhitelistedProcessWithPath("code", "/usr/share/code/");
    addWhitelistedProcessWithPath("code", "/opt/visual-studio-code/");
    addWhitelistedProcessWithPath("code", "/snap/code/");
    
    // Electron apps
    addWhitelistedProcessWithPath("electron", "/.config/");
    addWhitelistedProcessWithPath("electron", "/opt/");
    addWhitelistedProcessWithPath("electron", "/usr/lib/");
    
    // Browsers
    addWhitelistedProcessWithPath("chrome", "/opt/google/chrome/");
    addWhitelistedProcessWithPath("chrome", "/usr/bin/");
    addWhitelistedProcessWithPath("firefox", "/usr/lib/firefox/");
    addWhitelistedProcessWithPath("firefox", "/usr/bin/");
    addWhitelistedProcessWithPath("firefox", "/snap/firefox/");
    
    // Communication apps
    addWhitelistedProcessWithPath("Discord", "/.config/discord/");
    addWhitelistedProcessWithPath("Discord", "/opt/discord/");
    addWhitelistedProcessWithPath("slack", "/.config/Slack/");
    addWhitelistedProcessWithPath("slack", "/usr/lib/slack/");
    addWhitelistedProcessWithPath("telegram-desktop", "/usr/bin/");
    addWhitelistedProcessWithPath("telegram-desktop", "/.local/share/TelegramDesktop/");
    
    // Music/Media
    addWhitelistedProcessWithPath("spotify", "/usr/share/spotify/");
    addWhitelistedProcessWithPath("spotify", "/snap/spotify/");
    addWhitelistedProcessWithPath("spotify", "/opt/spotify/");
    
    // VirtualBox processes
    addWhitelistedProcessWithPath("VBoxClient", "/usr/bin/");
    addWhitelistedProcessWithPath("VBoxService", "/usr/sbin/");
    addWhitelistedProcessWithPath("iprt-VBoxTscThread", "/usr/");
    
    // System processes that might appear with paths
    addWhitelistedProcessWithPath("bluetoothd", "/usr/lib/");
    addWhitelistedProcessWithPath("bluetoothd", "/usr/libexec/");
    
    // Whitelist path prefixes (directories that are generally safe)
    m_whitelistedPathPrefixes.insert("/usr/bin/");
    m_whitelistedPathPrefixes.insert("/usr/sbin/");
    m_whitelistedPathPrefixes.insert("/usr/lib/");
    m_whitelistedPathPrefixes.insert("/usr/libexec/");
    m_whitelistedPathPrefixes.insert("/usr/share/");
    m_whitelistedPathPrefixes.insert("/bin/");
    m_whitelistedPathPrefixes.insert("/sbin/");
    m_whitelistedPathPrefixes.insert("/lib/");
    m_whitelistedPathPrefixes.insert("/lib64/");
    m_whitelistedPathPrefixes.insert("/snap/");
    m_whitelistedPathPrefixes.insert("/opt/");
    m_whitelistedPathPrefixes.insert("/var/lib/snapd/");
    
    if (m_verbose) {
        std::cout << "Loaded hardcoded defaults:\n"
                  << "  - " << m_processNameToRequiredPaths.size() 
                  << " process names with required paths\n"
                  << "  - " << m_whitelistedPathPrefixes.size() 
                  << " whitelisted path prefixes" << std::endl;
    }
}

void ProcessMonitor::loadDefaultWhitelists() {
    // IMPROVED: Try to load from config file first
    // If no config file found, fall back to hardcoded defaults
    
    if (!loadDefaultConfigFile()) {
        // No config file found, use hardcoded defaults
        loadHardcodedDefaults();
    }
}

void ProcessMonitor::addWhitelistedPath(const std::string& path) {
    m_whitelistedPathPrefixes.insert(path);
}

void ProcessMonitor::addWhitelistedProcess(const std::string& name) {
    // Adding a process without path requirements - be careful with this!
    m_whitelistedProcessNames.insert(name);
}

void ProcessMonitor::addWhitelistedProcessWithPath(const std::string& name, 
                                                    const std::string& pathPrefix) {
    // This is the SECURE way to whitelist - requires both name AND path to match
    m_processNameToRequiredPaths[name].push_back(pathPrefix);
}

void ProcessMonitor::clearWhitelists() {
    m_whitelistedPaths.clear();
    m_whitelistedProcessNames.clear();
    m_whitelistedPathPrefixes.clear();
    m_processNameToRequiredPaths.clear();
}

void ProcessMonitor::parseWhitelistLine(const std::string& line) {
    std::string trimmedLine = trim(line);
    
    // Skip empty lines and comments
    if (trimmedLine.empty() || trimmedLine[0] == '#') {
        return;
    }
    
    // Check for PATH: prefix (path-only whitelist)
    if (startsWith(trimmedLine, "PATH:")) {
        std::string path = trim(trimmedLine.substr(5));
        if (!path.empty()) {
            addWhitelistedPath(path);
            if (m_verbose) {
                std::cout << "  Whitelisted path prefix: " << path << "\n";
            }
        }
        return;
    }
    
    // Check if line contains a path separator (name:path format)
    size_t colonPos = trimmedLine.find(':');
    if (colonPos != std::string::npos) {
        // Format: name:path
        std::string name = trim(trimmedLine.substr(0, colonPos));
        std::string path = trim(trimmedLine.substr(colonPos + 1));
        
        if (!name.empty() && !path.empty()) {
            addWhitelistedProcessWithPath(name, path);
            if (m_verbose) {
                std::cout << "  Whitelisted: " << name << " -> " << path << "\n";
            }
        }
    } else {
        // Simple name only - use with caution!
        if (!trimmedLine.empty()) {
            addWhitelistedProcess(trimmedLine);
            if (m_verbose) {
                std::cout << "  Whitelisted (name only): " << trimmedLine << "\n";
            }
        }
    }
}

bool ProcessMonitor::loadWhitelistFromFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        if (m_verbose) {
            std::cerr << "Warning: Could not open whitelist file: " << filepath << std::endl;
        }
        return false;
    }
    
    if (m_verbose) {
        std::cout << "Loading whitelist from: " << filepath << std::endl;
    }
    
    std::string line;
    int lineCount = 0;
    while (std::getline(file, line)) {
        parseWhitelistLine(line);
        lineCount++;
    }
    
    if (m_verbose) {
        std::cout << "Processed " << lineCount << " lines from " << filepath << std::endl;
    }
    
    return true;
}

bool ProcessMonitor::loadWhitelistsFromDirectory(const std::string& dirpath) {
    if (!pathExists(dirpath)) {
        if (m_verbose) {
            std::cerr << "Warning: Whitelist directory does not exist: " 
                      << dirpath << std::endl;
        }
        return false;
    }
    
    if (m_verbose) {
        std::cout << "Loading whitelists from directory: " << dirpath << std::endl;
    }
    
#ifdef __linux__
    try {
        DIR* dir = opendir(dirpath.c_str());
        if (!dir) {
            if (m_verbose) {
                std::cerr << "Warning: Could not open directory: " << dirpath << std::endl;
            }
            return false;
        }
        
        struct dirent* entry;
        int filesLoaded = 0;
        
        while ((entry = readdir(dir)) != nullptr) {
            std::string filename = entry->d_name;
            
            // Skip . and .. and hidden files
            if (filename[0] == '.') {
                continue;
            }
            
            // Only process .txt and .conf files
            if (filename.size() < 4) {
                continue;
            }
            
            std::string ext = filename.substr(filename.size() - 4);
            if (ext != ".txt" && ext != "conf") {
                ext = filename.substr(filename.size() - 5);
                if (ext != ".conf") {
                    continue;
                }
            }
            
            std::string fullpath = dirpath;
            if (fullpath.back() != '/') {
                fullpath += '/';
            }
            fullpath += filename;
            
            // Check if it's a regular file
            struct stat st;
            if (stat(fullpath.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
                if (loadWhitelistFromFile(fullpath)) {
                    filesLoaded++;
                }
            }
        }
        
        closedir(dir);
        
        if (m_verbose) {
            std::cout << "Loaded " << filesLoaded << " whitelist files from " 
                      << dirpath << std::endl;
        }
        
        return filesLoaded > 0;
        
    } catch (const std::exception& e) {
        if (m_verbose) {
            std::cerr << "Error loading whitelists from directory: " 
                      << e.what() << std::endl;
        }
        return false;
    }
#else
    if (m_verbose) {
        std::cerr << "Directory whitelist loading not supported on this platform" << std::endl;
    }
    return false;
#endif
}

bool ProcessMonitor::isWhitelistedNameAndPath(const std::string& name, 
                                               const std::string& path) const {
    if (!m_enableWhitelist) {
        return false;
    }
    
    // Check if this name has required paths
    auto it = m_processNameToRequiredPaths.find(name);
    if (it != m_processNameToRequiredPaths.end()) {
        // Name is in the map - check if path matches any required prefix
        const auto& requiredPaths = it->second;
        for (const auto& requiredPath : requiredPaths) {
            if (path.find(requiredPath) != std::string::npos) {
                return true;  // Both name AND path match - legitimate!
            }
        }
        // Name matches but path doesn't - this is SUSPICIOUS!
        return false;
    }
    
    // Check if name is in the simple whitelist (less secure)
    if (m_whitelistedProcessNames.find(name) != m_whitelistedProcessNames.end()) {
        return true;
    }
    
    return false;
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
    
    // Check path prefix matches (system directories)
    for (const auto& prefix : m_whitelistedPathPrefixes) {
        if (path.find(prefix) == 0) {  // Must start with prefix
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
            contains(path, "/snap/")) {
            return true;
        }
    }
    
    return false;
}

bool ProcessMonitor::isWhitelisted(const Process& p) const {
    if (!m_enableWhitelist) {
        return false;
    }
    
    // CRITICAL FIX: Check both name AND path together for processes with required paths
    if (isWhitelistedNameAndPath(p.name, p.path)) {
        if (m_verbose) {
            std::cout << "  [WHITELIST] Process '" << p.name 
                      << "' at path '" << p.path << "' is whitelisted" << std::endl;
        }
        return true;
    }
    
    // Check if path alone is whitelisted (for system binaries)
    if (isWhitelistedPath(p.path)) {
        if (m_verbose) {
            std::cout << "  [WHITELIST] Path '" << p.path << "' is whitelisted" << std::endl;
        }
        return true;
    }
    
    // If name is in required paths map but we got here, it means the path didn't match
    // This is SUSPICIOUS - a process using a whitelisted name from wrong location!
    if (m_processNameToRequiredPaths.find(p.name) != m_processNameToRequiredPaths.end()) {
        if (m_verbose) {
            std::cout << "  [SUSPICIOUS] Process '" << p.name 
                      << "' uses whitelisted name but wrong path: " << p.path << std::endl;
        }
        return false;  // Explicitly not whitelisted - flag as suspicious
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
        
        // NOW check whitelist AFTER all suspicious checks
        // This allows us to log when something suspicious is whitelisted
        if (isSuspicious) {
            if (isWhitelisted(p)) {
                if (m_verbose) {
                    std::cout << "  [WHITELIST] Suspicious behavior ignored for whitelisted process" 
                              << std::endl;
                }
                // Don't add to suspicious list
            } else {
                suspicious.push_back(p);
            }
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

bool ProcessMonitor::loadWhitelistFromFile(const std::string& filepath) { return false; }
bool ProcessMonitor::loadWhitelistsFromDirectory(const std::string& dirpath) { return false; }
bool ProcessMonitor::loadDefaultConfigFile() { return false; }
std::vector<std::string> ProcessMonitor::getDefaultConfigPaths() const { return {}; }
void ProcessMonitor::loadHardcodedDefaults() {}

#endif