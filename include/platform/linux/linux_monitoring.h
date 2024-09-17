#ifndef LINUX_MONITORING_H
#define LINUX_MONITORING_H
#include <atomic>
#include <pcap.h>

namespace LinuxMonitoring {
    extern std::atomic<bool> stopCapture;
    void monitorInterfaces();
    void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
}

#endif // LINUX_MONITORING_H