#include "logger.h"
#include <fstream>

std::ofstream Logger::logFile;

void Logger::init(const std::string& filePath) {
    logFile.open(filePath, std::ios::out | std::ios::app);
}

void Logger::log(const std::string& message) {
    logFile << message << std::endl;
}
