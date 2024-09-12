#include "linux_firewall.h"
#include <fstream>
#include <cstdlib>

namespace LinuxFirewall {
    std::vector<std::string> rules; // Define the rules vector

    void loadRules(const std::string& configFilePath) {
        std::ifstream configFile(configFilePath);
        std::string line;
        while (std::getline(configFile, line)) {
            rules.push_back(line);
        }
    }

    void applyRules() {
        for (const auto& rule : rules) {
            std::string command = "iptables " + rule;
            system(command.c_str());
        }
    }
}