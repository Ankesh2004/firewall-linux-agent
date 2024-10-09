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

namespace LinuxMonitoring {

    pcap_dumper_t *pcapDumper = nullptr;

    const char* pcapFilePath = "/tmp/captured_packets.pcap";
    const int INIT_PROCESS_PID = 1;

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
                } catch (...) {
                    return -1;
                }
            }
        }
        return -1; // Process not found
    }

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

    void logPacketInfo(const std::string& logMessage) {
        std::cout << logMessage << std::endl;
        Logger::log(logMessage);
    }

    void handleTcpPacket(const u_char *packet, const struct ip *ipHeader, bool isSource) {
        const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        uint16_t port = isSource ? ntohs(tcpHeader->source) : ntohs(tcpHeader->dest);
        std::string logMessage = "TCP Packet - " + std::string(isSource ? "Source" : "Destination") + " Port: " + std::to_string(port);
        logPacketInfo(logMessage);

        int pid = getProcessIdForPort(port, "tcp");
        std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
        logMessage = (isSource ? "Source" : "Destination") + " Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
        logPacketInfo(logMessage);
    }

    void handleUdpPacket(const u_char *packet, const struct ip *ipHeader, bool isSource) {
        const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        uint16_t port = isSource ? ntohs(udpHeader->source) : ntohs(udpHeader->dest);
        std::string logMessage = "UDP Packet - " + std::string(isSource ? "Source" : "Destination") + " Port: " + std::to_string(port);
        logPacketInfo(logMessage);

        int pid = getProcessIdForPort(port, "udp");
        std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
        logMessage = (isSource ? "Source" : "Destination") + " Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
        logPacketInfo(logMessage);
    }

    void handleIcmpPacket() {
        std::string logMessage = "ICMP Packet";
        logPacketInfo(logMessage);
        std::string processName = getProcessName(INIT_PROCESS_PID);
        logMessage = "ICMP Handler Process: " + processName + " (PID: " + std::to_string(INIT_PROCESS_PID) + ")";
        logPacketInfo(logMessage);
    }

    void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        pcap_dumper_t *pcapDumper = reinterpret_cast<pcap_dumper_t*>(userData);
        pcap_dump(reinterpret_cast<u_char*>(pcapDumper), pkthdr, packet); // Write packet to .pcap file
        const struct ether_header *ethHeader = (struct ether_header *)packet;

        if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
            const struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
            std::string logMessage = "Captured IP packet from " + std::string(inet_ntoa(ipHeader->ip_src)) + " to " + std::string(inet_ntoa(ipHeader->ip_dst));
            logPacketInfo(logMessage);

            std::string srcIp = std::string(inet_ntoa(ipHeader->ip_src));
            bool isSource = (srcIp == "192.168.142.132");

            switch (ipHeader->ip_p) {
                case IPPROTO_TCP:
                    handleTcpPacket(packet, ipHeader, isSource);
                    break;
                case IPPROTO_UDP:
                    handleUdpPacket(packet, ipHeader, isSource);
                    break;
                case IPPROTO_ICMP:
                    handleIcmpPacket();
                    break;
                default:
                    logMessage = "Other IP Protocol: " + std::to_string(static_cast<int>(ipHeader->ip_p));
                    logPacketInfo(logMessage);
                    logMessage = "Unknown Process for Protocol: " + std::to_string(static_cast<int>(ipHeader->ip_p));
                    logPacketInfo(logMessage);
                    break;
            }
        } else if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP) {
            std::string logMessage = "Captured ARP packet";
            logPacketInfo(logMessage);
            std::string processName = getProcessName(INIT_PROCESS_PID); // Using PID 1 as a placeholder
            logMessage = "ARP Handler Process: " + processName + " (PID: " + std::to_string(INIT_PROCESS_PID) + ")";
            logPacketInfo(logMessage);
        } else {
            std::string logMessage = "Captured non-IP packet";
            logPacketInfo(logMessage);
            logMessage = "Unknown Process for non-IP packet";
            logPacketInfo(logMessage);
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
