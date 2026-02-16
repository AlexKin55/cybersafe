#pragma once

#include "icryptor.hpp"
#include <unordered_map>

class KeyGetterFromFile : public IKeyGetter {
public:

    KeyGetterFromFile() = default;
    virtual ~KeyGetterFromFile() = default;

    virtual void LoadKey(const SubjectInfo& subjectInfo, std::span<char> key) override;
    virtual std::expected<std::vector<char>, std::string_view> GetKey(const SubjectInfo& subjectInfo) override;

private:

    struct VectorHasher {
        size_t operator()(const std::vector<char>& v) const {
            return std::hash<std::string_view>{}(std::string_view(v.data(), v.size()));
        }
    };

    std::unordered_map<std::vector<char>, const std::vector<char>, VectorHasher> m_context;
};

