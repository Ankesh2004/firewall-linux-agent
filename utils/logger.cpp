#include "logger.h"
#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <ctime>

std::ofstream Logger::logFile;
std::mutex Logger::logMutex;

void Logger::init(const std::string& logFilePath) {
    logFile.open(logFilePath, std::ios::out | std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file: " << logFilePath << std::endl;
    }
}

void Logger::log(const std::string& message) {
    std::lock_guard<std::mutex> guard(logMutex);
    if (logFile.is_open()) {
        std::time_t now = std::time(nullptr);
        logFile << std::ctime(&now) << ": " << message << std::endl;
    } else {
        std::cerr << "Log file is not open. Message: " << message << std::endl;
    }
}