#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>

class Logger {
public:
    static void init(const std::string &logFilePath);
    static void log(const std::string &message);
};

#endif // LOGGER_H