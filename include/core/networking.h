#ifndef NETWORKING_H
#define NETWORKING_H

#include <string>

void configureNetworkInterface(const std::string& interface, const std::string& ip);
void bringInterfaceUp(const std::string& interface);
void bringInterfaceDown(const std::string& interface);

#endif // NETWORKING_H
