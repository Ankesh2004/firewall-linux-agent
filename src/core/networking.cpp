#include "networking.h"
#include "platform/linux/linux_networking.h"

void configureNetworkInterface(const std::string& interface, const std::string& address) {
    LinuxNetworking::setInterfaceAddress(interface, address);
}

void bringInterfaceUp(const std::string& interface) {
    LinuxNetworking::setInterfaceState(interface, true);
}

void bringInterfaceDown(const std::string& interface) {
    LinuxNetworking::setInterfaceState(interface, false);
}