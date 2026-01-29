#include "utils.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <cstdlib>

bool isTempPath(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    
    return path.find("/tmp") == 0 || 
           path.find("/var/tmp") == 0 ||
           path.find("/dev/shm") == 0;
}

bool isHiddenPath(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    
    size_t pos = 0;
    while ((pos = path.find("/.", pos)) != std::string::npos) {
        if (pos + 2 < path.length() && path[pos + 2] == '.') {
            pos += 3;
            continue;
        }
        
        if (pos + 2 < path.length() && path[pos + 2] != '/') {
            return true;
        }
        pos++;
    }
    
    return false;
}

bool pathExists(const std::string& path) {
    if (path.empty() || path == "unknown") {
        return false;
    }
    
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

std::string getHomeDirectory() {
    const char* home = std::getenv("HOME");
    if (home != nullptr) {
        return std::string(home);
    }
    
    struct passwd* pw = getpwuid(getuid());
    if (pw != nullptr && pw->pw_dir != nullptr) {
        return std::string(pw->pw_dir);
    }
    
    return "";
}

bool isInHomeDirectory(const std::string& path) {
    if (path.empty() || path == "unknown") {
        return false;
    }
    
    if (path.find("/home/") == 0) {
        return true;
    }
    
    std::string home = getHomeDirectory();
    if (!home.empty() && path.find(home) == 0) {
        return true;
    }
    
    return false;
}

bool getProcessUID(int pid, int& uid) {
    std::ifstream file("/proc/" + std::to_string(pid) + "/status");
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.rfind("Uid:", 0) == 0) {
            std::istringstream iss(line);
            std::string label;
            iss >> label >> uid;
            return true;
        }
    }
    
    return false;
}

bool isNumeric(const std::string& str) {
    if (str.empty()) {
        return false;
    }
    
    return std::all_of(str.begin(), str.end(), ::isdigit);
}

int safeStringToInt(const std::string& str, int defaultValue) {
    try {
        size_t pos;
        int value = std::stoi(str, &pos);
        
        if (pos == str.length()) {
            return value;
        }
    } catch (const std::invalid_argument&) {
    } catch (const std::out_of_range&) {
    }
    
    return defaultValue;
}

std::string trim(const std::string& str) {
    auto start = std::find_if(str.begin(), str.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    });
    
    auto end = std::find_if(str.rbegin(), str.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base();
    
    return (start < end) ? std::string(start, end) : std::string();
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

bool startsWith(const std::string& str, const std::string& prefix) {
    if (prefix.length() > str.length()) {
        return false;
    }
    return str.compare(0, prefix.length(), prefix) == 0;
}

bool contains(const std::string& str, const std::string& substr) {
    return str.find(substr) != std::string::npos;
}

bool isKnownGoodPath(const std::string& path) {
    if (path.empty() || path == "unknown") {
        return false;
    }
    
    const std::vector<std::string> goodPaths = {
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
        "/usr/local/bin/", "/usr/local/sbin/",
        "/lib/", "/usr/lib/", "/lib64/", "/usr/lib64/",
        "/opt/", "/snap/"
    };
    
    for (const auto& goodPath : goodPaths) {
        if (path.find(goodPath) == 0) {
            return true;
        }
    }
    
    return false;
}

bool hasSuspiciousChars(const std::string& str) {
    if (str.empty()) {
        return false;
    }
    
    for (char c : str) {
        if (!std::isprint(static_cast<unsigned char>(c)) && 
            c != '\n' && c != '\t' && c != '\r') {
            return true;
        }
    }
    
   
    const std::vector<std::string> suspiciousPatterns = {
        "$", "`", ";", "|", "&", "&&", "||"
    };
    
    for (const auto& pattern : suspiciousPatterns) {
        if (str.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}
