#ifndef LINUX_MONITORING_H
#define LINUX_MONITORING_H

#include <pcap.h>

namespace LinuxMonitoring {
    void monitorInterfaces();
    void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
}

#endif // LINUX_MONITORING_H