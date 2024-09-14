#include "logger.h"
#include <fstream>
#include <iostream>

std::ofstream logFile;

void Logger::init(const std::string &logFilePath) {
    logFile.open(logFilePath, std::ios::out | std::ios::app);
    if (!logFile.is_open()) {
        throw std::runtime_error("Failed to open log file: " + logFilePath);
    }
}

void Logger::log(const std::string &message) {
    if (logFile.is_open()) {
        logFile << message << std::endl;
    }
}