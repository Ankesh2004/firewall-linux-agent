#ifndef LINUX_FIREWALL_H
#define LINUX_FIREWALL_H

#include <string>
#include <vector>

namespace LinuxFirewall {
    void loadRules(const std::string& configFilePath);
    void applyRules();

    extern std::vector<std::string> rules;
}

#endif // LINUX_FIREWALL_H
