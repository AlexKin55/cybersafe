#pragma once

#include <string>
#include <span>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

struct SubjectInfo {
    uid_t uid;
    gid_t gid;
    pid_t pid;
};

class IInterceptor {
public:
    virtual ~IInterceptor() = default;

    virtual bool Permit(const std::string& path, int mask, const SubjectInfo& subject) const = 0;
    virtual void TransformData(const std::string& path, std::span<char> data, off_t offset) const = 0;
    virtual void LogAccess(const std::string& path, const SubjectInfo& subject, bool allowed) const = 0;
};
