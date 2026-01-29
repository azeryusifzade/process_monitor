#ifndef PROCESS_H
#define PROCESS_H

#include <string>
#include <vector>
#include <optional>
#include <stdexcept>
#include <set>

// Represents a running process with all relevant information
struct Process {
    int pid;
    std::string name;
    std::string path;
    std::string cmdline;
    int uid;
    
    // Additional useful fields
    std::string state;
    unsigned long long startTime;
    
    Process() : pid(0), uid(-1), startTime(0) {}
};

// Exception class for process monitoring errors
class ProcessMonitorException : public std::runtime_error {
public:
    explicit ProcessMonitorException(const std::string& msg) 
        : std::runtime_error(msg) {}
};

// Main process monitoring class
class ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor();
    
    // List all processes on the system
    std::vector<Process> listProcesses();
    
    // Analyze processes and return suspicious ones
    std::vector<Process> analyzeSuspicious(const std::vector<Process>& procs);
    
    // Get detailed information about a specific process
    std::optional<Process> getProcessInfo(int pid);
    
    // Configuration
    void setVerbose(bool verbose) { m_verbose = verbose; }
    void setMinPidForEmptyCmdCheck(int minPid) { m_minPidForEmptyCmdCheck = minPid; }
    void setEnableWhitelist(bool enable) { m_enableWhitelist = enable; }
    
    // Whitelist management
    void addWhitelistedPath(const std::string& path);
    void addWhitelistedProcess(const std::string& name);
    void loadDefaultWhitelists();
    void clearWhitelists();
    
private:
    bool m_verbose;
    int m_minPidForEmptyCmdCheck;
    bool m_enableWhitelist;
    
    std::set<std::string> m_whitelistedPaths;
    std::set<std::string> m_whitelistedProcessNames;
    std::set<std::string> m_whitelistedPathPrefixes;
    
    // Helper methods
    bool isSystemName(const std::string& name) const;
    bool isRealSystemProcess(const Process& p) const;
    bool isWhitelisted(const Process& p) const;
    bool isWhitelistedPath(const std::string& path) const;
    bool isWhitelistedName(const std::string& name) const;
    
    bool readProcessName(int pid, std::string& name) const;
    bool readProcessPath(int pid, std::string& path) const;
    bool readProcessCmdline(int pid, std::string& cmdline) const;
    bool readProcessState(int pid, std::string& state) const;
    bool readProcessStartTime(int pid, unsigned long long& startTime) const;
};

#endif // PROCESS_H