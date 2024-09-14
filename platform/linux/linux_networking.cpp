#include "linux_networking.h"
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <array>

namespace LinuxNetworking {
    bool isAddressAssigned(const std::string& interface, const std::string& address) {
        std::string command = "ip addr show " + interface + " | grep " + address;
        return (system(command.c_str()) == 0);
    }

    void removeInterfaceAddress(const std::string& interface, const std::string& address) {
        std::string command = "ip addr del " + address + " dev " + interface;
        if (system(command.c_str()) != 0) {
            std::cerr << "Failed to remove address from interface: " << interface << std::endl;
        }
    }

    void setInterfaceAddress(const std::string& interface, const std::string& address) {
        if (isAddressAssigned(interface, address)) {
            std::cerr << "Address " << address << " is already assigned to interface: " << interface << std::endl;
            removeInterfaceAddress(interface, address);
        }

        std::string command = "ip addr add " + address + " dev " + interface;
        if (system(command.c_str()) != 0) {
            std::cerr << "Failed to set address for interface: " << interface << std::endl;
        }
    }

    void setInterfaceState(const std::string& interface, bool up) {
        std::string command = "ip link set dev " + interface + (up ? " up" : " down");
        if (system(command.c_str()) != 0) {
            std::cerr << "Failed to set state for interface: " << interface << std::endl;
        }
    }
}