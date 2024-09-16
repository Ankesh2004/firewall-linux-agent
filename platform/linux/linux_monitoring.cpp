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
#include <ctime>


namespace LinuxMonitoring
{

    pcap_dumper_t *pcapDumper = nullptr;
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
// pcap file path 
const char* pcapFilePath = "/tmp/captured_packets.pcap";

// Function to get process ID for a given port and protocol
int getProcessIdForPort(uint16_t port, const std::string& protocol) {
    std::string command = "ss -tulnp | grep '" + protocol + "' | grep ':" + std::to_string(port) + "'";
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


void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    pcap_dumper_t *pcapDumper = reinterpret_cast<pcap_dumper_t*>(userData);
    pcap_dump(reinterpret_cast<u_char*>(pcapDumper), pkthdr, packet); // Write packet to .pcap file
    const struct ether_header *ethHeader = (struct ether_header *)packet;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        const struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
        std::string logMessage = "Captured IP packet from " + std::string(inet_ntoa(ipHeader->ip_src)) + " to " + std::string(inet_ntoa(ipHeader->ip_dst));
        std::cout << logMessage << std::endl;
        Logger::log(logMessage);

        std::string srcIp = std::string(inet_ntoa(ipHeader->ip_src));
        if (srcIp == "192.168.142.132") {
            switch (ipHeader->ip_p) {
                case IPPROTO_TCP: {
                    const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                    uint16_t srcPort = ntohs(tcpHeader->source);
                    logMessage = "TCP Packet - Source Port: " + std::to_string(srcPort) + ", Destination Port: " + std::to_string(ntohs(tcpHeader->dest));
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);

                    int pid = getProcessIdForPort(srcPort, "tcp");
                    std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
                    logMessage = "Source Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);
                    break;
                }
                case IPPROTO_UDP: {
                    const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                    uint16_t srcPort = ntohs(udpHeader->source);
                    logMessage = "UDP Packet - Source Port: " + std::to_string(srcPort) + ", Destination Port: " + std::to_string(ntohs(udpHeader->dest));
                    std::cout << logMessage << std::endl;
                    Logger::log(logMessage);

                    int pid = getProcessIdForPort(srcPort, "udp");
                    std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
                    logMessage = "Source Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
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
        } else {
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

    // Flush the pcap dump file to ensure data is written
    pcap_dump_flush(pcapDumper);
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
    
    Logger::log("Successfully opened device ens33 for capture");

    const char* pcapFilePath = "captured_packets.pcap";
    pcap_dumper_t *pcapDumper = pcap_dump_open(handle, pcapFilePath);
    if (pcapDumper == nullptr) {
        std::string errorMessage = "Failed to open dump file: " + std::string(pcap_geterr(handle));
        std::cerr << errorMessage << std::endl;
        Logger::log(errorMessage);
        pcap_close(handle);
        return;
    }
    
    Logger::log("Successfully opened pcap dump file: " + std::string(pcapFilePath));

    Logger::log("Starting packet capture loop...");
    int result = pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(pcapDumper));
    if (result < 0) {
        std::string errorMessage = "pcap_loop() failed: " + std::string(pcap_geterr(handle));
        std::cerr << errorMessage << std::endl;
        Logger::log(errorMessage);
    } else {
        Logger::log("Packet capture loop completed successfully");
    }

    pcap_dump_close(pcapDumper);
    pcap_close(handle);
    Logger::log("Closed pcap dump file and capture handle");
}

}
