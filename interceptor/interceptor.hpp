#pragma once

#include "subjectInfo.hpp"

#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

class IInterceptor {
public:
    virtual ~IInterceptor() = default;

    virtual bool Permit(int mask, const SubjectInfo& subject) const = 0;
    virtual uint64_t Write(const SubjectInfo& subject, std::span<char> data, off_t offset) = 0;
    virtual uint64_t Read(const SubjectInfo& subject, std::vector<char>& data, off_t offset) = 0;
    virtual void LogAccess(const SubjectInfo& subject, bool allowed) const = 0;
};
