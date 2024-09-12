#ifndef LOGGER_H
#define LOGGER_H

#include <string>

namespace Logger {
    void init(const std::string& filePath);
    void log(const std::string& message);
}

#endif // LOGGER_H
