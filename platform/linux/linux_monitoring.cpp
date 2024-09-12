#include "linux_monitoring.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

namespace LinuxMonitoring {

    void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        const struct ether_header *ethHeader;
        ethHeader = (struct ether_header *) packet;

        if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
            const struct ip *ipHeader;
            ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
            std::cout << "Captured IP packet from " << inet_ntoa(ipHeader->ip_src) << " to " << inet_ntoa(ipHeader->ip_dst) << std::endl;
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