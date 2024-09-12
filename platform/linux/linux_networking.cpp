#include "linux_networking.h"
#include <cstdlib>
#include <iostream>

namespace LinuxNetworking {
    void setInterfaceAddress(const std::string& interface, const std::string& address) {
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