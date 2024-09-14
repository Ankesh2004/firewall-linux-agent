#include "linux_monitoring.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include "../utils/logger.h"
#include <vector>
#include <ifaddrs.h>

namespace LinuxMonitoring
{
// Helper function to execute a command and get the output
std::string exec(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// Function to get process ID for a given port and protocol
int getProcessIdForPort(uint16_t port, const std::string& protocol) {
    std::string command = "ss -tulnp | grep '" + protocol + "' | grep ':" + std::to_string(port) + "'";
    std::string output = exec(command);
    std::string pidStr = "pid=";
    size_t pos = output.find(pidStr);
    if (pos != std::string::npos) {
        pos += pidStr.length();
        size_t endPos = output.find(',', pos);
        if (endPos != std::string::npos) {
            std::string pid = output.substr(pos, endPos - pos);
            return std::stoi(pid);
        }
    }
    return -1; // Process not found
}

// Function to get process name based on PID
std::string getProcessName(int pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream file(path);
    if (file.is_open()) {
        std::string processName;
        std::getline(file, processName);
        return processName;
    }
    return "Unknown";
}

// Helper function to get all local IP addresses
std::vector<std::string> getLocalIPAddresses() {
    std::vector<std::string> localIPs;
    struct ifaddrs *ifAddrStruct = nullptr;
    getifaddrs(&ifAddrStruct);
    while (ifAddrStruct != nullptr) {
        if (ifAddrStruct->ifa_addr->sa_family == AF_INET) { // check for IPv4
            char addressBuffer[INET_ADDRSTRLEN];
            void* tmpAddrPtr = &((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            localIPs.push_back(std::string(addressBuffer));  // Store as std::string
        }
        ifAddrStruct = ifAddrStruct->ifa_next;
    }
    freeifaddrs(ifAddrStruct);
    return localIPs;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const struct ether_header *ethHeader = (struct ether_header *)packet;
    static std::vector<std::string> localIPs = getLocalIPAddresses(); // Get local IPs only once

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        const struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
        std::string srcIP = inet_ntoa(ipHeader->ip_src);  // Convert to std::string
        std::string dstIP = inet_ntoa(ipHeader->ip_dst);  // Convert to std::string

        std::string logMessage = "Captured IP packet from " + srcIP + " to " + dstIP;
        std::cout << logMessage << std::endl;
        Logger::log(logMessage);

        bool isOutgoing = (std::find(localIPs.begin(), localIPs.end(), srcIP) != localIPs.end());
        bool isIncoming = (std::find(localIPs.begin(), localIPs.end(), dstIP) != localIPs.end());

        switch (ipHeader->ip_p) {
            case IPPROTO_TCP: {
                const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                uint16_t srcPort = ntohs(tcpHeader->source);
                uint16_t destPort = ntohs(tcpHeader->dest);

                logMessage = "TCP Packet - Source Port: " + std::to_string(srcPort) + ", Destination Port: " + std::to_string(destPort);
                std::cout << logMessage << std::endl;
                Logger::log(logMessage);

                if (isOutgoing) {
                    int pid = getProcessIdForPort(srcPort, "tcp");
                    std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
                    logMessage = "Outgoing Packet - Source Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                } else if (isIncoming) {
                    int pid = getProcessIdForPort(destPort, "tcp");
                    std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
                    logMessage = "Incoming Packet - Destination Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                }
                std::cout << logMessage << std::endl;
                Logger::log(logMessage);
                break;
            }
            case IPPROTO_UDP: {
                const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                uint16_t srcPort = ntohs(udpHeader->source);
                uint16_t destPort = ntohs(udpHeader->dest);

                logMessage = "UDP Packet - Source Port: " + std::to_string(srcPort) + ", Destination Port: " + std::to_string(destPort);
                std::cout << logMessage << std::endl;
                Logger::log(logMessage);

                if (isOutgoing) {
                    int pid = getProcessIdForPort(srcPort, "udp");
                    std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
                    logMessage = "Outgoing Packet - Source Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                } else if (isIncoming) {
                    int pid = getProcessIdForPort(destPort, "udp");
                    std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
                    logMessage = "Incoming Packet - Destination Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                }
                std::cout << logMessage << std::endl;
                Logger::log(logMessage);
                break;
            }
            default: {
                logMessage = "Other IP Protocol: " + std::to_string(static_cast<int>(ipHeader->ip_p));
                std::cout << logMessage << std::endl;
                Logger::log(logMessage);
                break;
            }
        }
    } else {
        std::string logMessage = "Captured non-IP packet";
        std::cout << logMessage << std::endl;
        Logger::log(logMessage);
    }
}

void monitorInterfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::string errorMessage = "Failed to open device ens33: " + std::string(errbuf);
        std::cerr << errorMessage << std::endl;
        Logger::log(errorMessage);
        return;
    }

    if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
        std::string errorMessage = "pcap_loop() failed: " + std::string(pcap_geterr(handle));
        std::cerr << errorMessage << std::endl;
        Logger::log(errorMessage);
        return;
    }

    pcap_close(handle);
}

}
