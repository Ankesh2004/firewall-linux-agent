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
        // Use 'ss' without the 'l' flag to include both listening and established sockets
        std::string command = "ss -" + protocol + "npt | grep ':" + std::to_string(port) + "'";
        std::string output = exec(command);
        std::string pidStr = "pid=";
        size_t pos = output.find(pidStr);
        if (pos != std::string::npos) {
            pos += pidStr.length();
            size_t endPos = output.find(',', pos);
            if (endPos == std::string::npos) {
                endPos = output.find(' ', pos);
            }
            if (endPos != std::string::npos) {
                std::string pid = output.substr(pos, endPos - pos);
                try {
                    return std::stoi(pid);
                }
                catch (...) {
                    return -1;
                }
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

    // Function to determine if the packet is outgoing
    bool isOutgoingPacket(const struct ip* ipHeader) {
        // Get host IP addresses
        // This is a simplified assumption. In a real scenario, you might need to retrieve and cache the host's IP addresses.
        // Here, we'll assume that packets with a source IP matching one of the host's interfaces are outgoing.
        // For demonstration, we'll assume the host's IP is "192.168.1.100". Replace this with dynamic retrieval as needed.
        const char* hostIp = "192.168.1.100";
        std::string srcIp = inet_ntoa(ipHeader->ip_src);
        return srcIp == hostIp;
    }

    void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        const struct ether_header *ethHeader = (struct ether_header *)packet;

        if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
            const struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
            std::string logMessage = "Captured IP packet from " + std::string(inet_ntoa(ipHeader->ip_src)) + " to " + std::string(inet_ntoa(ipHeader->ip_dst));
            std::cout << logMessage << std::endl;
            Logger::log(logMessage);

            bool outgoing = isOutgoingPacket(ipHeader);
            std::string direction = outgoing ? "Outgoing" : "Incoming";

            switch (ipHeader->ip_p) {
                case IPPROTO_TCP: {
                    const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                    uint16_t port = outgoing ? ntohs(tcpHeader->source) : ntohs(tcpHeader->dest);
                    logMessage = "TCP Packet - " + direction + " Port: " + std::to_string(port);
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);

                    std::string protocol = "tcp";
                    int pid = getProcessIdForPort(port, protocol);
                    std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
                    if (outgoing) {
                        logMessage = "Source Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                    }
                    else {
                        logMessage = "Destination Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                    }
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    break;
                }
                case IPPROTO_UDP: {
                    const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                    uint16_t port = outgoing ? ntohs(udpHeader->source) : ntohs(udpHeader->dest);
                    logMessage = "UDP Packet - " + direction + " Port: " + std::to_string(port);
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);

                    std::string protocol = "udp";
                    int pid = getProcessIdForPort(port, protocol);
                    std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
                    if (outgoing) {
                        logMessage = "Source Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                    }
                    else {
                        logMessage = "Destination Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                    }
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    break;
                }
                case IPPROTO_ICMP: {
                    logMessage = "ICMP Packet - " + direction;
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    std::string processName = outgoing ? getProcessName(1) : getProcessName(1); // PID 1 is usually the init process
                    if (outgoing) {
                        logMessage = "Source Process: " + processName + " (PID: 1)";
                    }
                    else {
                        logMessage = "ICMP Handler Process: " + processName + " (PID: 1)";
                    }
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    break;
                }
                default: {
                    logMessage = "Other IP Protocol: " + std::to_string(static_cast<int>(ipHeader->ip_p)) + " - " + direction;
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    logMessage = "Unknown Process for Protocol: " + std::to_string(static_cast<int>(ipHeader->ip_p));
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    break;
                }
            }
        }
        else if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP) {
            std::string logMessage = "Captured ARP packet";
            std::cout << logMessage << std::endl;
            Logger::log(logMessage);
            std::string processName = getProcessName(1); // Using PID 1 as a placeholder
            logMessage = "ARP Handler Process: " + processName + " (PID: 1)";
            std::cout << logMessage << std::endl;
            Logger::log(logMessage);
        }
        else {
            std::string logMessage = "Captured non-IP packet";
            std::cout << logMessage << std::endl;
            Logger::log(logMessage);
            logMessage = "Unknown Process for non-IP packet";
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