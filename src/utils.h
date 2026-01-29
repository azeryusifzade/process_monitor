#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>

bool isTempPath(const std::string& path);
bool isHiddenPath(const std::string& path);
bool pathExists(const std::string& path);
std::string getHomeDirectory();
bool isInHomeDirectory(const std::string& path);

bool getProcessUID(int pid, int& uid);
bool isNumeric(const std::string& str);
int safeStringToInt(const std::string& str, int defaultValue = 0);

std::string trim(const std::string& str);
std::vector<std::string> split(const std::string& str, char delimiter);
bool startsWith(const std::string& str, const std::string& prefix);
bool contains(const std::string& str, const std::string& substr);

bool isKnownGoodPath(const std::string& path);
bool hasSuspiciousChars(const std::string& str);

#endif // UTILS_H
