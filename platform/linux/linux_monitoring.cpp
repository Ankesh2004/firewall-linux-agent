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

namespace LinuxMonitoring {

    std::string getProcessName(int pid) {
        std::string procPath = "/proc/" + std::to_string(pid) + "/comm";
        std::ifstream procFile(procPath);
        std::string processName;
        if (procFile.is_open()) {
            std::getline(procFile, processName);
        }
        return processName;
    }

    int getProcessIdForPort(uint16_t port, const char* protocol) {
        std::string command = "ss -tlnp | grep " + std::string(protocol) + " | grep :" + std::to_string(port);
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) return -1;

        char buffer[128];
        std::string result = "";
        while (!feof(pipe)) {
            if (fgets(buffer, 128, pipe) != NULL)
                result += buffer;
        }
        pclose(pipe);

        size_t pidPos = result.find("pid=");
        if (pidPos != std::string::npos) {
            size_t commaPos = result.find(",", pidPos);
            if (commaPos != std::string::npos) {
                std::string pidStr = result.substr(pidPos + 4, commaPos - (pidPos + 4));
                return std::stoi(pidStr);
            }
        }
        return -1;
    }

    void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        const struct ether_header *ethHeader;
        ethHeader = (struct ether_header *) packet;

        if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
            const struct ip *ipHeader;
            ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
            std::cout << "Captured IP packet from " << inet_ntoa(ipHeader->ip_src) << " to " << inet_ntoa(ipHeader->ip_dst) << std::endl;

            switch (ipHeader->ip_p) {
                case IPPROTO_TCP: {
                    const struct tcphdr *tcpHeader;
                    tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                    uint16_t destPort = ntohs(tcpHeader->dest);
                    std::cout << "TCP Packet - Source Port: " << ntohs(tcpHeader->source) << ", Destination Port: " << destPort << std::endl;
                    int pid = getProcessIdForPort(destPort, "tcp");
                    if (pid != -1) {
                        std::string processName = getProcessName(pid);
                        std::cout << "Destination Process: " << processName << " (PID: " << pid << ")" << std::endl;
                    }
                    break;
                }
                case IPPROTO_UDP: {
                    const struct udphdr *udpHeader;
                    udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                    uint16_t destPort = ntohs(udpHeader->dest);
                    std::cout << "UDP Packet - Source Port: " << ntohs(udpHeader->source) << ", Destination Port: " << destPort << std::endl;
                    int pid = getProcessIdForPort(destPort, "udp");
                    if (pid != -1) {
                        std::string processName = getProcessName(pid);
                        std::cout << "Destination Process: " << processName << " (PID: " << pid << ")" << std::endl;
                    }
                    break;
                }
                case IPPROTO_ICMP:
                    std::cout << "ICMP Packet" << std::endl;
                    break;
                default:
                    std::cout << "Other IP Protocol: " << static_cast<int>(ipHeader->ip_p) << std::endl;
                    break;
            }
        } else if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP) {
            std::cout << "Captured ARP packet" << std::endl;
        } else {
            std::cout << "Captured non-IP packet" << std::endl;
        }
    }

    void monitorInterfaces() {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "Failed to open device ens33: " << errbuf << std::endl;
            return;
        }

        if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
            std::cerr << "pcap_loop() failed: " << pcap_geterr(handle) << std::endl;
            return;
        }

        pcap_close(handle);
    }
}