#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>

namespace Logger {
    extern std::ofstream logFile; // Declare logFile
    void init(const std::string& filePath);
    void log(const std::string& message);
}

#endif // LOGGER_H