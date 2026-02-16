#pragma once

#include "subjectInfo.hpp"

#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

class IKeyGetter {
public:
    IKeyGetter() = default;
    virtual ~IKeyGetter() = default;

    virtual void LoadKey(const SubjectInfo& subjectInfo, std::span<char> key) = 0;
    virtual std::expected<std::vector<char>, std::string_view> GetKey(const SubjectInfo& subjectInfo) = 0;
};

class ICryptor {
public:
    ICryptor() = default;
    virtual ~ICryptor() = default;

    virtual std::expected<std::vector<char>, std::string_view>
        Decrypt(const SubjectInfo& subjectInfo, std::span<char> data, off_t offset) = 0;
    virtual std::expected<std::vector<char>, std::string_view>
        Encrypt(const SubjectInfo& subjectInfo, std::span<char> data, off_t offset) = 0;
};
