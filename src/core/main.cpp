#include "networking.h"
#include "firewall.h"
#include "monitoring.h"
#include "utils/logger.h"
#include "utils/config.h"
#include "platform/linux/linux_monitoring.h" // Add this line
#include <pcap.h>
#include <sys/capability.h>
#include <iostream>
#include <fstream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <thread>

void setCapabilities() {
    cap_t caps = cap_get_proc();
    if (caps == NULL) {
        std::cerr << "Failed to get capabilities" << std::endl;
        exit(EXIT_FAILURE);
    }

    cap_value_t capList[] = {CAP_NET_ADMIN, CAP_NET_RAW};
    if (cap_set_flag(caps, CAP_EFFECTIVE, 2, capList, CAP_SET) == -1) {
        std::cerr << "Failed to set capabilities" << std::endl;
        cap_free(caps);
        exit(EXIT_FAILURE);
    }

    if (cap_set_proc(caps) == -1) {
        std::cerr << "Failed to apply capabilities" << std::endl;
        cap_free(caps);
        exit(EXIT_FAILURE);
    }

    cap_free(caps);
}

int main() {
    Logger::init("logs/agent.log");

    std::ifstream configFile("config/firewall_rules.conf");
    if (!configFile.is_open()) {
        std::cerr << "Failed to open config file: config/firewall_rules.conf" << std::endl;
        return 1;
    }
    configFile.close();

    Config::load("config/firewall_rules.conf");

    setCapabilities();

    configureNetworkInterface("ens33", "192.168.1.10/24");
    bringInterfaceUp("ens33");

    applyFirewallRules("config/firewall_rules.conf");

    std::thread monitoringThread(LinuxMonitoring::monitorInterfaces);
    monitoringThread.join();

    return 0;
}