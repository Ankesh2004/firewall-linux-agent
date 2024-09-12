#include "logger.h"
#include <fstream>

namespace Logger {
    std::ofstream logFile; // Define logFile

    void init(const std::string& filePath) {
        logFile.open(filePath, std::ios::out | std::ios::app);
    }

    void log(const std::string& message) {
        logFile << message << std::endl;
    }
}