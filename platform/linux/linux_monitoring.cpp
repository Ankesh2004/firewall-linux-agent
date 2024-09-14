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
    // std::string getProcessName(int pid)
    // {
    //     std::string procPath = "/proc/" + std::to_string(pid) + "/comm";
    //     std::ifstream procFile(procPath);
    //     std::string processName = "Unknown";
    //     if (procFile.is_open())
    //     {
    //         std::getline(procFile, processName);
    //     }
    //     else
    //     {
    //         Logger::log("Failed to open process file: " + procPath);
    //     }
    //     return processName;
    // }

    // int getProcessIdForPort(uint16_t port, const char *protocol)
    // {
    //     std::string command = "ss -tlnp | grep " + std::string(protocol) + " | grep :" + std::to_string(port);
    //     FILE *pipe = popen(command.c_str(), "r");
    //     if (!pipe)
    //     {
    //         Logger::log("Failed to execute command: " + command);
    //         return -1;
    //     }

    //     char buffer[128];
    //     std::string result = "";
    //     while (!feof(pipe))
    //     {
    //         if (fgets(buffer, 128, pipe) != NULL)
    //             result += buffer;
    //     }
    //     pclose(pipe);

    //     size_t pidPos = result.find("pid=");
    //     Logger::log("ss command output: " + result);
    //     if (pidPos != std::string::npos)
    //     {
    //         size_t commaPos = result.find(",", pidPos);
    //         if (commaPos != std::string::npos)
    //         {
    //             std::string pidStr = result.substr(pidPos + 4, commaPos - (pidPos + 4));
    //             Logger::log("Extracted PID string: " + pidStr);
    //             try
    //             {
    //                 int pid = std::stoi(pidStr);
    //                 Logger::log("Found PID: " + std::to_string(pid));
    //                 return pid;
    //             }
    //             catch (const std::exception &e)
    //             {
    //                 Logger::log("Failed to convert PID to integer: " + pidStr);
    //             }
    //         }
    //     }

    //     return -1;
    // }

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

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        const struct ether_header *ethHeader = (struct ether_header *)packet;

        if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
            const struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
            std::string logMessage = "Captured IP packet from " + std::string(inet_ntoa(ipHeader->ip_src)) + " to " + std::string(inet_ntoa(ipHeader->ip_dst));
            std::cout << logMessage << std::endl;
            Logger::log(logMessage);

            switch (ipHeader->ip_p) {
                case IPPROTO_TCP: {
                    const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                    uint16_t destPort = ntohs(tcpHeader->dest);
                    logMessage = "TCP Packet - Source Port: " + std::to_string(ntohs(tcpHeader->source)) + ", Destination Port: " + std::to_string(destPort);
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);

                    int pid = getProcessIdForPort(destPort, "tcp");
                    std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
                    logMessage = "Destination Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    break;
                }
                case IPPROTO_UDP: {
                    const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                    uint16_t destPort = ntohs(udpHeader->dest);
                    logMessage = "UDP Packet - Source Port: " + std::to_string(ntohs(udpHeader->source)) + ", Destination Port: " + std::to_string(destPort);
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);

                    int pid = getProcessIdForPort(destPort, "udp");
                    std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
                    logMessage = "Destination Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    break;
                }
                case IPPROTO_ICMP: {
                    logMessage = "ICMP Packet";
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    std::string processName = getProcessName(1); // PID 1 is usually the init process
                    logMessage = "ICMP Handler Process: " + processName + " (PID: 1)";
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    break;
                }
                default: {
                    logMessage = "Other IP Protocol: " + std::to_string(static_cast<int>(ipHeader->ip_p));
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    logMessage = "Unknown Process for Protocol: " + std::to_string(static_cast<int>(ipHeader->ip_p));
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    break;
                }
            }
        } else if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP) {
            std::string logMessage = "Captured ARP packet";
            std::cout << logMessage << std::endl;
            Logger::log(logMessage);
            std::string processName = getProcessName(1); // Using PID 1 as a placeholder
            logMessage = "ARP Handler Process: " + processName + " (PID: 1)";
            std::cout << logMessage << std::endl;
            Logger::log(logMessage);
        } else {
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