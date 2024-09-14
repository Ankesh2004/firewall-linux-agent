#include "logger.h"
#include <fstream>
#include <iostream>

std::ofstream logFile;

void Logger::log(const std::string &message) {
    if (!logFile.is_open()) {
        logFile.open("logs/agent.log", std::ios::app);
    }
    if (logFile.is_open()) {
        logFile << message << std::endl;
    } else {
        std::cerr << "Failed to open log file" << std::endl;
    }
}