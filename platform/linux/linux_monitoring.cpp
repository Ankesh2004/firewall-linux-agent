#include "linux_monitoring.h"
#include <iostream>
#include <thread>
#include <chrono>

void LinuxMonitoring::monitorInterfaces() {
    while (true) {
        system("vnstat -i eth0");
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}
