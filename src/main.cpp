#include "process.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>

// Color codes for terminal output
namespace Color {
    const char* RESET = "\033[0m";
    const char* RED = "\033[31m";
    const char* GREEN = "\033[32m";
    const char* YELLOW = "\033[33m";
    const char* BLUE = "\033[34m";
    const char* MAGENTA = "\033[35m";
    const char* CYAN = "\033[36m";
    const char* BOLD = "\033[1m";
}

// Print usage information
void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]\n\n"
              << "Linux Process Monitor - Detect suspicious processes\n\n"
              << "Options:\n"
              << "  -h, --help              Show this help message\n"
              << "  -v, --verbose           Enable verbose output\n"
              << "  -a, --all               Show all processes (not just suspicious)\n"
              << "  -p, --pid <pid>         Show information for specific PID\n"
              << "  -m, --min-pid <num>     Minimum PID for empty cmdline check (default: 1000)\n"
              << "  --no-color              Disable colored output\n"
              << "  --no-whitelist          Disable whitelist filtering (show all detections)\n"
              << "  --add-whitelist-name <name>       Add process name to whitelist\n"
              << "  --add-whitelist-path <path>       Add path prefix to whitelist\n"
              << "  --add-whitelist-name-path <name:path>  Add name with required path\n"
              << "  --whitelist-file <file>           Load whitelist from file\n"
              << "  --whitelist-dir <directory>       Load whitelists from directory\n"
              << "\nWhitelist File Format:\n"
              << "  # Comments start with #\n"
              << "  processname              (whitelist by name only - less secure)\n"
              << "  processname:/path/prefix (whitelist name+path - more secure)\n"
              << "\nExamples:\n"
              << "  " << programName << " --verbose\n"
              << "  " << programName << " --whitelist-file /etc/procmon/whitelist.txt\n"
              << "  " << programName << " --whitelist-dir /etc/procmon/whitelist.d/\n"
              << "  " << programName << " --add-whitelist-name-path myapp:/opt/myapp/\n"
              << std::endl;
}

// Print process information in a formatted way
void printProcess(const Process& p, bool useColor = true) {
    const char* suspColor = useColor ? Color::RED : "";
    const char* labelColor = useColor ? Color::CYAN : "";
    const char* reset = useColor ? Color::RESET : "";
    
    std::cout << suspColor << "[SUSPICIOUS PROCESS]" << reset << "\n"
              << labelColor << "  PID:       " << reset << p.pid << "\n"
              << labelColor << "  Name:      " << reset << p.name << "\n"
              << labelColor << "  UID:       " << reset << p.uid << "\n"
              << labelColor << "  Path:      " << reset << p.path << "\n"
              << labelColor << "  Command:   " << reset 
              << (p.cmdline.empty() ? "<empty>" : p.cmdline) << "\n";
    
    if (!p.state.empty()) {
        std::cout << labelColor << "  State:     " << reset << p.state << "\n";
    }
    
    std::cout << std::endl;
}

// Print summary table
void printSummary(const std::vector<Process>& all, 
                  const std::vector<Process>& suspicious,
                  bool useColor = true) {
    const char* boldColor = useColor ? Color::BOLD : "";
    const char* greenColor = useColor ? Color::GREEN : "";
    const char* redColor = useColor ? Color::RED : "";
    const char* yellowColor = useColor ? Color::YELLOW : "";
    const char* reset = useColor ? Color::RESET : "";
    
    std::cout << "\n" << boldColor << "=== SCAN SUMMARY ===" << reset << "\n\n"
              << "Total processes scanned: " << greenColor << all.size() << reset << "\n"
              << "Suspicious processes found: ";
    
    if (suspicious.empty()) {
        std::cout << greenColor << "0" << reset << " ✓\n";
    } else {
        std::cout << redColor << suspicious.size() << reset;
        if (suspicious.size() < 5) {
            std::cout << " " << yellowColor << "(review recommended)" << reset << "\n";
        } else {
            std::cout << " " << redColor << "(HIGH - immediate review required!)" << reset << "\n";
        }
    }
    
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    bool verbose = false;
    bool showAll = false;
    bool useColor = true;
    bool enableWhitelist = true;
    int specificPid = -1;
    int minPid = 1000;
    std::vector<std::string> customWhitelistNames;
    std::vector<std::string> customWhitelistPaths;
    std::vector<std::string> customWhitelistNamePaths;
    std::vector<std::string> whitelistFiles;
    std::vector<std::string> whitelistDirs;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "-a" || arg == "--all") {
            showAll = true;
        } else if (arg == "--no-color") {
            useColor = false;
        } else if (arg == "--no-whitelist") {
            enableWhitelist = false;
        } else if (arg == "-p" || arg == "--pid") {
            if (i + 1 < argc) {
                specificPid = std::atoi(argv[++i]);
            } else {
                std::cerr << "Error: --pid requires a PID argument\n";
                return 1;
            }
        } else if (arg == "-m" || arg == "--min-pid") {
            if (i + 1 < argc) {
                minPid = std::atoi(argv[++i]);
            } else {
                std::cerr << "Error: --min-pid requires a number argument\n";
                return 1;
            }
        } else if (arg == "--add-whitelist-name") {
            if (i + 1 < argc) {
                customWhitelistNames.push_back(argv[++i]);
            } else {
                std::cerr << "Error: --add-whitelist-name requires a name argument\n";
                return 1;
            }
        } else if (arg == "--add-whitelist-path") {
            if (i + 1 < argc) {
                customWhitelistPaths.push_back(argv[++i]);
            } else {
                std::cerr << "Error: --add-whitelist-path requires a path argument\n";
                return 1;
            }
        } else if (arg == "--add-whitelist-name-path") {
            if (i + 1 < argc) {
                customWhitelistNamePaths.push_back(argv[++i]);
            } else {
                std::cerr << "Error: --add-whitelist-name-path requires a name:path argument\n";
                return 1;
            }
        } else if (arg == "--whitelist-file") {
            if (i + 1 < argc) {
                whitelistFiles.push_back(argv[++i]);
            } else {
                std::cerr << "Error: --whitelist-file requires a file path argument\n";
                return 1;
            }
        } else if (arg == "--whitelist-dir") {
            if (i + 1 < argc) {
                whitelistDirs.push_back(argv[++i]);
            } else {
                std::cerr << "Error: --whitelist-dir requires a directory path argument\n";
                return 1;
            }
        } else {
            std::cerr << "Error: Unknown option: " << arg << "\n\n";
            printUsage(argv[0]);
            return 1;
        }
    }
    
    try {
        ProcessMonitor monitor;
        monitor.setVerbose(verbose);
        monitor.setMinPidForEmptyCmdCheck(minPid);
        monitor.setEnableWhitelist(enableWhitelist);
        
        // Load whitelist files
        for (const auto& file : whitelistFiles) {
            if (!monitor.loadWhitelistFromFile(file)) {
                std::cerr << "Warning: Failed to load whitelist file: " << file << "\n";
            }
        }
        
        // Load whitelist directories
        for (const auto& dir : whitelistDirs) {
            if (!monitor.loadWhitelistsFromDirectory(dir)) {
                std::cerr << "Warning: Failed to load whitelists from directory: " << dir << "\n";
            }
        }
        
        // Add custom whitelist entries
        for (const auto& name : customWhitelistNames) {
            monitor.addWhitelistedProcess(name);
            if (verbose) {
                std::cout << "Added '" << name << "' to whitelist (name only)\n";
            }
        }
        
        for (const auto& path : customWhitelistPaths) {
            monitor.addWhitelistedPath(path);
            if (verbose) {
                std::cout << "Added path '" << path << "' to whitelist\n";
            }
        }
        
        for (const auto& namePath : customWhitelistNamePaths) {
            size_t colonPos = namePath.find(':');
            if (colonPos != std::string::npos) {
                std::string name = namePath.substr(0, colonPos);
                std::string path = namePath.substr(colonPos + 1);
                monitor.addWhitelistedProcessWithPath(name, path);
                if (verbose) {
                    std::cout << "Added '" << name << "' with required path '" 
                              << path << "' to whitelist\n";
                }
            } else {
                std::cerr << "Warning: Invalid name:path format: " << namePath << "\n";
            }
        }
        
        // Handle specific PID query
        if (specificPid > 0) {
            if (verbose) {
                std::cout << "Querying information for PID " << specificPid << "...\n\n";
            }
            
            auto processOpt = monitor.getProcessInfo(specificPid);
            if (processOpt.has_value()) {
                printProcess(processOpt.value(), useColor);
                return 0;
            } else {
                std::cerr << "Error: Could not get information for PID " << specificPid << "\n";
                return 1;
            }
        }
        
        // Scan all processes
        const char* boldColor = useColor ? Color::BOLD : "";
        const char* reset = useColor ? Color::RESET : "";
        
        if (verbose) {
            std::cout << boldColor << "Scanning system processes..." << reset << "\n";
            if (enableWhitelist) {
                std::cout << "Whitelist filtering: " << Color::GREEN << "ENABLED" << reset 
                          << " (use --no-whitelist to disable)\n";
            } else {
                std::cout << "Whitelist filtering: " << Color::YELLOW << "DISABLED" << reset << "\n";
            }
            std::cout << std::endl;
        }
        
        auto processes = monitor.listProcesses();
        
        if (processes.empty()) {
            std::cerr << "Warning: No processes found. Are you running with sufficient permissions?\n";
            return 1;
        }
        
        auto suspicious = monitor.analyzeSuspicious(processes);
        
        // Print results
        if (showAll) {
            std::cout << "\n" << boldColor << "=== ALL PROCESSES ===" << reset << "\n\n";
            for (const auto& p : processes) {
                std::cout << "PID: " << std::setw(6) << p.pid
                          << " | UID: " << std::setw(5) << p.uid
                          << " | Name: " << std::setw(20) << std::left << p.name
                          << " | Path: " << p.path << "\n";
            }
            std::cout << std::endl;
        }
        
        if (!suspicious.empty()) {
            const char* redColor = useColor ? Color::RED : "";
            std::cout << "\n" << boldColor << redColor 
                      << "=== SUSPICIOUS PROCESSES DETECTED ===" 
                      << reset << "\n\n";
            
            for (const auto& p : suspicious) {
                printProcess(p, useColor);
            }
            
            if (!enableWhitelist) {
                const char* yellowColor = useColor ? Color::YELLOW : "";
                std::cout << yellowColor 
                          << "Note: Whitelist is disabled. Many of these may be false positives.\n"
                          << "Run without --no-whitelist to filter known safe processes."
                          << reset << "\n\n";
            }
        } else {
            const char* greenColor = useColor ? Color::GREEN : "";
            const char* boldColor = useColor ? Color::BOLD : "";
            std::cout << "\n" << boldColor << greenColor 
                      << "✓ No suspicious processes detected" 
                      << reset << "\n\n";
        }
        
        printSummary(processes, suspicious, useColor);
        
        // Exit code: 0 if no suspicious processes, 1 if found
        return suspicious.empty() ? 0 : 1;
        
    } catch (const ProcessMonitorException& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected error: " << e.what() << "\n";
        return 2;
    }
}