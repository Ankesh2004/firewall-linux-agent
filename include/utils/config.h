#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <map>

namespace Config {
    void load(const std::string& filePath);
    std::string get(const std::string& key);

    extern std::map<std::string, std::string> configMap;
}

#endif // CONFIG_H
