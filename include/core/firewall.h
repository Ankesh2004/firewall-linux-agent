#ifndef FIREWALL_H
#define FIREWALL_H

#include <string>
#include "platform/linux/linux_firewall.h"

void applyFirewallRules(const std::string& configFilePath);
LinuxFirewall::Action checkPacket(const LinuxFirewall::PacketInfo& packetInfo);

#endif // FIREWALL_H
