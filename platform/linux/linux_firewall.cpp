#include "linux_firewall.h"
#include <fstream>
#include <cstdlib>
#include <iostream>

namespace LinuxFirewall {
    std::vector<std::string> rules; // Define the rules vector

    void loadRules(const std::string& configFilePath) {
        std::ifstream configFile(configFilePath);
        if (!configFile.is_open()) {
            std::cerr << "Failed to open config file: " << configFilePath << std::endl;
            exit(EXIT_FAILURE);
        }

        std::string line;
        while (std::getline(configFile, line)) {
            rules.push_back(line);
        }
    }

    void applyRules() {
        for (const auto& rule : rules) {
            std::string command = "iptables " + rule;
            if (system(command.c_str()) != 0) {
                std::cerr << "Failed to apply rule: " << rule << std::endl;
            }
        }
    }
}