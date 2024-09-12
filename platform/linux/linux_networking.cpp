#include "linux_networking.h"
#include <cstdlib>

void LinuxNetworking::assignIPAddress(const std::string& interface, const std::string& ip) {
    std::string command = "ip addr add " + ip + " dev " + interface;
    system(command.c_str());
}

void LinuxNetworking::setInterfaceState(const std::string& interface, bool up) {
    std::string command = "ip link set dev " + interface + (up ? " up" : " down");
    system(command.c_str());
}
