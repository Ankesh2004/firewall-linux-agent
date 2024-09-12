#include "firewall.h"
#include "platform/linux/linux_firewall.h"

void applyFirewallRules(const std::string& configFilePath) {
    LinuxFirewall::loadRules(configFilePath);
    LinuxFirewall::applyRules();
}