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
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        logFile << std::put_time(std::localtime(&now_c), "%F %T") << " - " << message << std::endl;
        logFile.flush(); // Ensure the message is written immediately
    } else {
        std::cerr << "Log file is not open. Message: " << message << std::endl;
    }
}