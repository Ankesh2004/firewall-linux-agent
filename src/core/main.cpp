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

std::string getNetworkInterface() {
    std::ifstream configFile("config/network.conf");
    std::string line;
    std::string interface;

    while (std::getline(configFile, line)) {
        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            if (key == "interface") {
                interface = value;
                break;
            }
        }
    }

    // If the interface is empty, call the script to set it
    if (interface.empty()) {
        std::cout << "Network interface not set. Running script to detect and set interface..." << std::endl;
        system("../../platform/linux/set_network_interface.sh");

        // Re-read the configuration file to get the updated interface
        configFile.clear(); // Clear EOF flag
        configFile.seekg(0, std::ios::beg); // Rewind to the beginning of the file

        while (std::getline(configFile, line)) {
            std::istringstream iss(line);
            std::string key, value;
            if (std::getline(iss, key, '=') && std::getline(iss, value)) {
                if (key == "interface") {
                    interface = value;
                    break;
                }
            }
        }
    }

    return interface.empty() ? "ens33" : interface; // Default value if still empty
}

int main() {
    try {
        // Initialize logging
        Logger::init("logs/agent.log");

        // Load configuration
        Config::load("config/firewall_rules.conf");

        // Set capabilities
        setCapabilities();

        // Get network interface from configuration
        std::string networkInterface = getNetworkInterface();

        // Configure network interface
        configureNetworkInterface(networkInterface, "192.168.1.10/24");
        bringInterfaceUp("ens33");

        // Apply firewall rules
        applyFirewallRules("config/firewall_rules.conf");

        // Start monitoring interfaces
        LinuxMonitoring::monitorInterfaces();

        // Add a delay to allow some packets to be captured
        std::this_thread::sleep_for(std::chrono::seconds(30));
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        Logger::log(std::string("Error: ") + e.what());
        return 1;
    }

    return 0;
}