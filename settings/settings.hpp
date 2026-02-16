#pragma once

#include <unordered_map>
#include <memory>
#include <string>
#include <string_view>
#include <optional>
#include <vector>

class Settings {
public:

    explicit Settings(const std::string& configPath);

    std::optional<std::string_view> getParam(std::string_view paramName) const;
    std::optional<std::vector<std::string>> getParamAsVector(std::string_view paramName) const;
    bool isValid() const;
    
    using SettingsType = std::unordered_map<std::string, std::string>;

private:

    std::unique_ptr<const Settings::SettingsType> m_settings;
};