#ifndef LINUX_NETWORKING_H
#define LINUX_NETWORKING_H

#include <string>

namespace LinuxNetworking {
    void assignIPAddress(const std::string& interface, const std::string& ip);
    void setInterfaceState(const std::string& interface, bool up);
}

#endif // LINUX_NETWORKING_H
