#include "config.h"
#include <fstream>
#include <iostream>

std::map<std::string, std::string> Config::configMap;

void Config::load(const std::string& filePath) {
    std::ifstream configFile(filePath);
    std::string line;
    while (std::getline(configFile, line)) {
        auto delimiterPos = line.find("=");
        auto name = line.substr(0, delimiterPos);
        auto value = line.substr(delimiterPos + 1);
        configMap[name] = value;
    }
}

std::string Config::get(const std::string& key) {
    return configMap[key];
}
