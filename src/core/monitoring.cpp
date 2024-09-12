#include "monitoring.h"
#include "platform/linux/linux_monitoring.h"

void startMonitoring() {
    LinuxMonitoring::monitorInterfaces();
}
