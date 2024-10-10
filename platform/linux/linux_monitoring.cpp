#include "linux_monitoring.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <pcap.h>
#include <string>
#include <array>
#include <cstdlib>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <unordered_map>
#include <unistd.h>
#include <optional>
#include <fstream>
#include <sstream>
#include "../utils/logger.h"
#include <ctime>
#include <cstring>
#include <regex>

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

    class ProcessCache {
    private:
        struct CacheEntry {
            int pid;
            std::string processName;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::unordered_map<std::string, CacheEntry> cache;
        const std::chrono::seconds TTL;

    public:
        ProcessCache(int ttlSeconds = 60) : TTL(ttlSeconds) {}

        void set(const std::string& key, int pid, const std::string& processName) {
            cache[key] = {pid, processName, std::chrono::steady_clock::now()};
        }

        std::optional<std::pair<int, std::string>> get(const std::string& key) {
            auto it = cache.find(key);
            if (it != cache.end()) {
                if (std::chrono::steady_clock::now() - it->second.timestamp < TTL) {
                    return std::make_pair(it->second.pid, it->second.processName);
                } else {
                    cache.erase(it);
                }
            }
            return std::nullopt;
        }
    };

    ProcessCache processCache;

    std::string getProcessName(int pid) {
        std::string path = "/proc/" + std::to_string(pid) + "/comm";
        std::ifstream file(path);
        if (file.is_open()) {
            std::string processName;
            std::getline(file, processName);
            return processName;
        } else {
            if (errno == EACCES) {
                Logger::log("Permission denied when accessing " + path);
                return "Permission Denied";
            } else {
                Logger::log("Error accessing " + path + ": " + std::strerror(errno));
                return "Access Error";
            }
        }
    }

    std::pair<int, std::string> expensiveLookup(uint16_t port, const std::string& protocol) {
        std::string command = "ss -tulnp | grep '" + protocol + "' | grep ':" + std::to_string(port) + "'";
        std::string output;
        try {
            output = exec(command);
        } catch (const std::runtime_error& e) {
            Logger::log("Error executing ss command: " + std::string(e.what()));
            return {-1, "Error"};
        }

        std::istringstream iss(output);
        std::string line;
        while (std::getline(iss, line)) {
            std::regex pidRegex(R"(pid=(\d+))");
            std::smatch match;
            if (std::regex_search(line, match, pidRegex) && match.size() > 1) {
                try {
                    int pid = std::stoi(match[1].str());
                    std::string processName = getProcessName(pid);
                    return {pid, processName};
                } catch (const std::exception& e) {
                    Logger::log("Error converting PID to integer: " + std::string(e.what()));
                }
            }
        }
        Logger::log("No matching process found for port " + std::to_string(port) + " and protocol " + protocol);
        return {-1, "Unknown"};
    }

    // int getProcessIdForPort(uint16_t port, const std::string& protocol) {
    //     std::string command = "ss -tulnp | grep '" + protocol + "' | grep ':" + std::to_string(port) + "'";
    //     std::string output;
    //     try {
    //         output = exec(command);
    //     } catch (const std::runtime_error& e) {
    //         Logger::log("Error executing ss command: " + std::string(e.what()));
    //         return -1;
    //     }
        
    //     std::istringstream iss(output);
    //     std::string line;
    //     while (std::getline(iss, line)) {
    //         std::regex pidRegex(R"(pid=(\d+))");
    //         std::smatch match;
    //         if (std::regex_search(line, match, pidRegex) && match.size() > 1) {
    //             try {
    //                 return std::stoi(match[1].str());
    //             } catch (const std::exception& e) {
    //                 Logger::log("Error converting PID to integer: " + std::string(e.what()));
    //             }
    //         }
    //     }
    //     Logger::log("No matching process found for port " + std::to_string(port) + " and protocol " + protocol);
    //     return -1;
    // }

    // std::string getProcessName(int pid) {
    //     std::string path = "/proc/" + std::to_string(pid) + "/comm";
    //     std::ifstream file(path);
    //     if (file.is_open()) {
    //         std::string processName;
    //         std::getline(file, processName);
    //         return processName;
    //     } else {
    //         if (errno == EACCES) {
    //             Logger::log("Permission denied when accessing " + path);
    //             return "Permission Denied";
    //         } else {
    //             Logger::log("Error accessing " + path + ": " + std::strerror(errno));
    //             return "Access Error";
    //         }
    //     }
    // }

    

    std::pair<int, std::string> getProcessInfoForPort(uint16_t port, const std::string& protocol) {
        std::string cacheKey = protocol + ":" + std::to_string(port);
        auto cachedInfo = processCache.get(cacheKey);
        if (cachedInfo) {
            return *cachedInfo;
        }

        // If not in cache, perform the expensive lookup
        auto [pid, processName] = expensiveLookup(port, protocol);

        if (pid != -1) {
            processCache.set(cacheKey, pid, processName);
        }
        return {pid, processName};
    }

    void logPacketInfo(const std::string& logMessage) {
        std::cout << logMessage << std::endl;
        Logger::log(logMessage);
    }

    // void handleTcpPacket(const u_char *packet, const struct ip *ipHeader, bool isOutgoing) {
    //     const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    //     uint16_t localPort = isOutgoing ? ntohs(tcpHeader->source) : ntohs(tcpHeader->dest);
    //     uint16_t remotePort = isOutgoing ? ntohs(tcpHeader->dest) : ntohs(tcpHeader->source);
    //     std::string localIp = isOutgoing ? std::string(inet_ntoa(ipHeader->ip_src)) : std::string(inet_ntoa(ipHeader->ip_dst));
    //     std::string remoteIp = isOutgoing ? std::string(inet_ntoa(ipHeader->ip_dst)) : std::string(inet_ntoa(ipHeader->ip_src));

    //     std::string logMessage = "TCP Packet - Local " + localIp + ":" + std::to_string(localPort) + 
    //                              " <-> Remote " + remoteIp + ":" + std::to_string(remotePort) + 
    //                              (isOutgoing ? " (Outgoing)" : " (Incoming)");
    //     logPacketInfo(logMessage);

    //     int pid = getProcessIdForPort(localPort, "tcp");
    //     std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
    //     logMessage = "Local Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
    //     logPacketInfo(logMessage);
    // }

    void handleTcpPacket(const u_char *packet, const struct ip *ipHeader, bool isOutgoing) {
    const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    uint16_t localPort = isOutgoing ? ntohs(tcpHeader->source) : ntohs(tcpHeader->dest);
    uint16_t remotePort = isOutgoing ? ntohs(tcpHeader->dest) : ntohs(tcpHeader->source);
    std::string localIp = isOutgoing ? std::string(inet_ntoa(ipHeader->ip_src)) : std::string(inet_ntoa(ipHeader->ip_dst));
    std::string remoteIp = isOutgoing ? std::string(inet_ntoa(ipHeader->ip_dst)) : std::string(inet_ntoa(ipHeader->ip_src));

    std::string logMessage = "TCP Packet - Local " + localIp + ":" + std::to_string(localPort) + 
                             " <-> Remote " + remoteIp + ":" + std::to_string(remotePort) + 
                             (isOutgoing ? " (Outgoing)" : " (Incoming)");
    logPacketInfo(logMessage);

    // Get process information for the local port
    auto [pid, processName] = getProcessInfoForPort(localPort, "tcp");
    logMessage = "Local Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
    logPacketInfo(logMessage);

    // Identify and log common TCP protocols
    std::string protocolName;
    switch (localPort) {
        case 80:
            protocolName = "HTTP";
            break;
        case 443:
            protocolName = "HTTPS";
            break;
        case 20:
        case 21:
            protocolName = "FTP";
            break;
        case 22:
            protocolName = "SSH";
            break;
        case 23:
            protocolName = "Telnet";
            break;
        case 25:
            protocolName = "SMTP";
            break;
        case 110:
            protocolName = "POP3";
            break;
        case 143:
            protocolName = "IMAP";
            break;
        case 53:
            protocolName = "DNS";
            break;
        case 3306:
            protocolName = "MySQL";
            break;
        case 5432:
            protocolName = "PostgreSQL";
            break;
        case 3389:
            protocolName = "RDP";
            break;
        case 445:
            protocolName = "SMB";
            break;
        case 389:
            protocolName = "LDAP";
            break;
        case 1433:
            protocolName = "MSSQL";
            break;
        default:
            protocolName = "Unknown";
            break;
    }

    if (protocolName != "Unknown") {
        logMessage = "Identified Protocol: " + protocolName;
        logPacketInfo(logMessage);
    }
}

    // void handleUdpPacket(const u_char *packet, const struct ip *ipHeader, bool isOutgoing) {
    //     const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    //     uint16_t localPort = isOutgoing ? ntohs(udpHeader->source) : ntohs(udpHeader->dest);
    //     uint16_t remotePort = isOutgoing ? ntohs(udpHeader->dest) : ntohs(udpHeader->source);
    //     std::string localIp = isOutgoing ? std::string(inet_ntoa(ipHeader->ip_src)) : std::string(inet_ntoa(ipHeader->ip_dst));
    //     std::string remoteIp = isOutgoing ? std::string(inet_ntoa(ipHeader->ip_dst)) : std::string(inet_ntoa(ipHeader->ip_src));

    //     std::string logMessage = "UDP Packet - Local " + localIp + ":" + std::to_string(localPort) + 
    //                              " <-> Remote " + remoteIp + ":" + std::to_string(remotePort) + 
    //                              (isOutgoing ? " (Outgoing)" : " (Incoming)");
    //     logPacketInfo(logMessage);

    //     int pid = getProcessIdForPort(localPort, "udp");
    //     std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";

    //     if (pid != -1) {
    //         logMessage = "Local Process: " + processName + " (PID: " + std::to_string(pid) + ")";
    //     } else {
    //         logMessage = "Local Process: Unknown (PID: Unknown)";
    //         Logger::log("Unable to identify process for UDP port " + std::to_string(localPort));
    //     }
    //     logPacketInfo(logMessage);

    //     // Additional information about the packet
    //     size_t udpPayloadSize = ntohs(udpHeader->len) - sizeof(struct udphdr);
    //     logMessage = "UDP Payload Size: " + std::to_string(udpPayloadSize) + " bytes";
    //     logPacketInfo(logMessage);

    //     // Check for common UDP protocols based on port numbers
    //     std::string knownProtocol = identifyCommonUdpProtocol(localPort, remotePort);
    //     if (!knownProtocol.empty()) {
    //         logMessage = "Identified UDP Protocol: " + knownProtocol;
    //         logPacketInfo(logMessage);
    //     }
    // }

    // std::string identifyCommonUdpProtocol(uint16_t localPort, uint16_t remotePort) {
    //     std::unordered_map<uint16_t, std::string> commonPorts = {
    //         {53, "DNS"},
    //         {67, "DHCP Server"},
    //         {68, "DHCP Client"},
    //         {123, "NTP"},
    //         {161, "SNMP"},
    //         {500, "IKE (VPN)"},
    //         {1900, "SSDP (UPnP)"},
    //         {5353, "mDNS"}
    //     };

    //     auto checkPort = [&commonPorts](uint16_t port) -> std::string {
    //         auto it = commonPorts.find(port);
    //         return (it != commonPorts.end()) ? it->second : "";
    //     };

    //     std::string protocol = checkPort(localPort);
    //     if (protocol.empty()) {
    //         protocol = checkPort(remotePort);
    //     }

    //     return protocol;
    // }

void handleUdpPacket(const u_char *packet, const struct ip *ipHeader, bool isOutgoing) {
    const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    uint16_t localPort = isOutgoing ? ntohs(udpHeader->source) : ntohs(udpHeader->dest);
    uint16_t remotePort = isOutgoing ? ntohs(udpHeader->dest) : ntohs(udpHeader->source);
    std::string localIp = isOutgoing ? std::string(inet_ntoa(ipHeader->ip_src)) : std::string(inet_ntoa(ipHeader->ip_dst));
    std::string remoteIp = isOutgoing ? std::string(inet_ntoa(ipHeader->ip_dst)) : std::string(inet_ntoa(ipHeader->ip_src));

    std::string logMessage = "UDP Packet - Local " + localIp + ":" + std::to_string(localPort) + 
                             " <-> Remote " + remoteIp + ":" + std::to_string(remotePort) + 
                             (isOutgoing ? " (Outgoing)" : " (Incoming)");
    logPacketInfo(logMessage);

    // Get process information for the local port
    auto [pid, processName] = getProcessInfoForPort(localPort, "udp");
    logMessage = "Local Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
    logPacketInfo(logMessage);

    // Additional information about the packet
    size_t udpPayloadSize = ntohs(udpHeader->len) - sizeof(struct udphdr);
    logMessage = "UDP Payload Size: " + std::to_string(udpPayloadSize) + " bytes";
    logPacketInfo(logMessage);

    // Identify and log common UDP protocols
    std::string protocolName;
    switch (localPort) {
        case 53:
            protocolName = "DNS";
            break;
        case 67:
        case 68:
            protocolName = "DHCP";
            break;
        case 69:
            protocolName = "TFTP";
            break;
        case 123:
            protocolName = "NTP";
            break;
        case 161:
        case 162:
            protocolName = "SNMP";
            break;
        case 500:
            protocolName = "IKE";
            break;
        case 514:
            protocolName = "Syslog";
            break;
        case 1812:
        case 1813:
            protocolName = "RADIUS";
            break;
        case 2049:
            protocolName = "NFS";
            break;
        case 5353:
            protocolName = "mDNS";
            break;
        default:
            protocolName = "Unknown";
            break;
    }

    if (protocolName != "Unknown") {
        logMessage = "Identified UDP Protocol: " + protocolName;
        logPacketInfo(logMessage);
    }
}

    // void handleIcmpPacket(const u_char *packet, const struct ip *ipHeader, bool isOutgoing) {
    //     const struct icmphdr *icmpHeader = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    //     std::string logMessage = "ICMP Packet - Type: " + std::to_string(icmpHeader->type) + ", Code: " + std::to_string(icmpHeader->code);
    //     logPacketInfo(logMessage);

    //     // Try to find the process using the 'ping' command as an example
    //     int pid = getProcessIdForCommand("ping");
    //     std::string processName = (pid != -1) ? getProcessName(pid) : "Unknown";
    //     logMessage = "ICMP Handler Process: " + processName + " (PID: " + (pid != -1 ? std::to_string(pid) : "Unknown") + ")";
    //     logPacketInfo(logMessage);
    // }
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
