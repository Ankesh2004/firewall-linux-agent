#ifndef LINUX_FIREWALL_H
#define LINUX_FIREWALL_H

#include <string>
#include <vector>

namespace LinuxFirewall {
    enum class Action { ACCEPT, DROP };
    enum class Direction { IN, OUT, ANY };

    struct FirewallRule {
        Action action;
        Direction direction;
        std::string protocol;
        std::string srcMac;
        std::string dstMac;
        std::string srcIp;
        std::string dstIp;
        std::string srcPort;
        std::string dstPort;
        std::string process;
    };

    struct PacketInfo {
        Direction direction;
        std::string protocol;
        std::string srcMac;
        std::string dstMac;
        std::string srcIp;
        std::string dstIp;
        std::string srcPort;
        std::string dstPort;
        std::string process;
    };

    void loadRules(const std::string& configFilePath);
    Action applyRules(const PacketInfo& packet);
}

#endif // LINUX_FIREWALL_H
