#include "firewall.h"
#include "platform/linux/linux_firewall.h"
#include "utils/logger.h"

void applyFirewallRules(const std::string& configFilePath) {
    LinuxFirewall::loadRules(configFilePath);
    // We don't need to call applyRules here anymore
    Logger::log("Firewall rules loaded from " + configFilePath);
}

LinuxFirewall::Action checkPacket(const LinuxFirewall::PacketInfo& packetInfo) {
    return LinuxFirewall::applyRules(packetInfo);
}