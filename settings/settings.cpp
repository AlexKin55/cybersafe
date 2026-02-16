#include "settings.hpp"
#include <yaml-cpp/yaml.h>

#include <iostream>
#include <sstream>

namespace {

void flattenYaml(const YAML::Node& node, Settings::SettingsType& res, const std::string& prefix = "") {
    for (auto const& it : node) {
        std::string key = it.first.as<std::string>();
        std::string fullKey = prefix.empty() ? key : prefix + "." + key;

        if (it.second.IsMap()) {
            flattenYaml(it.second, res, fullKey);
        } else {
            res[fullKey] = it.second.as<std::string>();
        }
    }
}

std::unique_ptr<Settings::SettingsType> loadYaml(const std::string& path) {
    auto settingsMap = std::make_unique<Settings::SettingsType>();

    try {
        YAML::Node config = YAML::LoadFile(path);
        Settings::SettingsType flatMap;

        flattenYaml(config, flatMap);
        return std::make_unique<Settings::SettingsType>(std::move(flatMap));
        
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
    return nullptr;
}
}

Settings::Settings(const std::string& configPath) 
    : m_settings(loadYaml(configPath)){
}

bool Settings::isValid() const {
    return !(!m_settings || m_settings->empty());
}

std::optional<std::string_view> Settings::getParam(std::string_view paramName) const {
    if (auto it = m_settings->find(std::string(paramName)); it != m_settings->end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<std::vector<std::string>> Settings::getParamAsVector(std::string_view paramName) const {
    auto it = m_settings->find(std::string(paramName));
    if (it != m_settings->end()) {
        const std::string& params = it->second;
        std::istringstream iss(params);
        
        return std::vector<std::string>{
            std::istream_iterator<std::string>{iss},
            std::istream_iterator<std::string>{}
        };
    }
    return std::nullopt;
}


