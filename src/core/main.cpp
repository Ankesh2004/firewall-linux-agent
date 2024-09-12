#include "networking.h"
#include "firewall.h"
#include "monitoring.h"
#include "utils/logger.h"
#include "utils/config.h"

int main() {
    Logger::init("logs/agent.log");
    Config::load("config/firewall_rules.conf");

    configureNetworkInterface("ens33", "192.168.1.10/24");
    bringInterfaceUp("ens33");

    applyFirewallRules("config/firewall_rules.conf");

    startMonitoring();

    return 0;
}
