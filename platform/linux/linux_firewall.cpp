#include "linux_firewall.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include "utils/logger.h" 

namespace LinuxFirewall {
    // enum class Action { ACCEPT, DROP };
    // enum class Direction { IN, OUT, ANY };
    // struct FirewallRule {
    //     Action action;
    //     Direction direction;
    //     std::string protocol;
    //     std::string srcMac;
    //     std::string dstMac;
    //     std::string srcIp;
    //     std::string dstIp;
    //     std::string srcPort;
    //     std::string dstPort;
    //     std::string process;
    // };
    // struct PacketInfo {
    //     Direction direction;
    //     std::string protocol;
    //     std::string srcMac;
    //     std::string dstMac;
    //     std::string srcIp;
    //     std::string dstIp;
    //     std::string srcPort;
    //     std::string dstPort;
    //     std::string process;
    // };
    std::vector<FirewallRule> rules;

    void loadRules(const std::string& configFilePath) {
        std::ifstream configFile(configFilePath);
        if (!configFile.is_open()) {
            std::cerr << "Failed to open config file: " << configFilePath << std::endl;
            return;
        }

        std::string line;
        while (std::getline(configFile, line)) {
            if (line.empty() || line[0] == '#') continue;

            std::istringstream iss(line);
            std::string token;
            std::vector<std::string> tokens;

            while (std::getline(iss, token, ',')) {
                tokens.push_back(token);
            }

            if (tokens.size() == 10) {
                FirewallRule rule;
                rule.action = tokens[0] == "ACCEPT" ? Action::ACCEPT : Action::DROP;
                rule.direction = tokens[1] == "IN" ? Direction::IN : (tokens[1] == "OUT" ? Direction::OUT : Direction::ANY);
                rule.protocol = tokens[2];
                rule.srcMac = tokens[3];
                rule.dstMac = tokens[4];
                rule.srcIp = tokens[5];
                rule.dstIp = tokens[6];
                rule.srcPort = tokens[7];
                rule.dstPort = tokens[8];
                rule.process = tokens[9];

                rules.push_back(rule);
            }
        }
    }

    bool matchRule(const FirewallRule& rule, const PacketInfo& packet) {
        if (rule.direction != Direction::ANY && rule.direction != packet.direction) return false;
        if (rule.protocol != "*" && rule.protocol != packet.protocol) return false;
        if (rule.srcMac != "*" && rule.srcMac != packet.srcMac) return false;
        if (rule.dstMac != "*" && rule.dstMac != packet.dstMac) return false;
        if (rule.srcIp != "*" && rule.srcIp != packet.srcIp) return false;
        if (rule.dstIp != "*" && rule.dstIp != packet.dstIp) return false;
        if (rule.srcPort != "*" && rule.srcPort != packet.srcPort) return false;
        if (rule.dstPort != "*" && rule.dstPort != packet.dstPort) return false;
        if (rule.process != "*" && rule.process != packet.process) return false;
        return true;
    }

    Action applyRules(const PacketInfo& packet) {
        Logger::log("Applying firewall rules to packet: " + packet.srcIp + ":" + packet.srcPort + " -> " + packet.dstIp + ":" + packet.dstPort);
        for (const auto& rule : rules) {
            if (matchRule(rule, packet)) {
                return rule.action;
            }
        }
        return Action::ACCEPT; // Default action if no rules match
    }
}