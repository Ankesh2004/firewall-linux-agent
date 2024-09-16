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
#include "core/firewall.h"

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
        packetInfo.srcIp = inet_ntoa(ipHeader->ip_src);
        packetInfo.dstIp = inet_ntoa(ipHeader->ip_dst);

        switch (ipHeader->ip_p) {
            case IPPROTO_TCP: {
                const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                packetInfo.protocol = "TCP";
                packetInfo.srcPort = std::to_string(ntohs(tcpHeader->source));
                packetInfo.dstPort = std::to_string(ntohs(tcpHeader->dest));
                break;
            }
            case IPPROTO_UDP: {
                const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                packetInfo.protocol = "UDP";
                packetInfo.srcPort = std::to_string(ntohs(udpHeader->source));
                packetInfo.dstPort = std::to_string(ntohs(udpHeader->dest));
                break;
            }
            case IPPROTO_ICMP: {
                packetInfo.protocol = "ICMP";
                packetInfo.srcPort = "*";
                packetInfo.dstPort = "*";
                break;
            }
            default: {
                packetInfo.protocol = "OTHER";
                packetInfo.srcPort = "*";
                packetInfo.dstPort = "*";
                break;
            }
        }
    } else if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP) {
        packetInfo.protocol = "ARP";
        packetInfo.srcIp = "*";
        packetInfo.dstIp = "*";
        packetInfo.srcPort = "*";
        packetInfo.dstPort = "*";
    } else {
        packetInfo.protocol = "UNKNOWN";
        packetInfo.srcIp = "*";
        packetInfo.dstIp = "*";
        packetInfo.srcPort = "*";
        packetInfo.dstPort = "*";
    }

    // Determine direction (this is a simplification, you may need to adjust based on your network setup)
    packetInfo.direction = (packetInfo.srcIp == "192.168.1.10") ? LinuxFirewall::Direction::OUT : LinuxFirewall::Direction::IN;

    // Get process name (this is a placeholder, you'll need to implement this based on your system)
    packetInfo.process = getProcessName(getProcessIdForPort(std::stoi(packetInfo.srcPort), packetInfo.protocol));

    // Apply firewall rules
    LinuxFirewall::Action action = checkPacket(packetInfo);

    if (action == LinuxFirewall::Action::DROP) {
        // Log that the packet was dropped
        Logger::log("Packet dropped: " + packetInfo.srcIp + ":" + packetInfo.srcPort + 
                    " -> " + packetInfo.dstIp + ":" + packetInfo.dstPort);
        return; // Don't process this packet further
    }

    std::string logMessage = "Packet: " + packetInfo.protocol + " " + packetInfo.srcIp + ":" + packetInfo.srcPort + 
                             " -> " + packetInfo.dstIp + ":" + packetInfo.dstPort + 
                             " Process: " + packetInfo.process + 
                             " Action: " + (action == LinuxFirewall::Action::ACCEPT ? "ACCEPT" : "DROP");

    Logger::log(logMessage);

    if (action == LinuxFirewall::Action::DROP) {
        // Here you would implement the actual packet dropping logic
        // This might involve using iptables or other system-specific methods
        Logger::log("Dropped packet based on firewall rules");
    }

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
