#pragma once
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <memory>
#include <vector>

constexpr std::string_view MAGIC_BYTES = "CYBERSAFE";
constexpr std::string_view AGENT_VERSION = "0.0.1";

using namespace std::string_view_literals;

#pragma pack(push, 1) 
struct CyberHead {
    char magicBytes[16];
    char agentVersion[16];
    char uuid[16];
};
#pragma pack(pop)

static_assert(sizeof(CyberHead) == 48, "CyberHead size must be exactly 48 bytes!");

std::expected<const struct SubjectInfo, std::string_view>
MakeSubjectInfo(const std::string& path, const uint64_t fileHandle);

struct SubjectInfo {
    uid_t m_uid = 0;
    gid_t m_gid = 0;
    pid_t m_pid = 0;
    std::string m_fileName;
    std::vector<char> m_uuid;
    uint64_t m_fileHandle = 0;

    std::expected<void, std::string_view> writeCyberHeader();

    friend std::expected<const struct SubjectInfo, std::string_view>
    MakeSubjectInfo(const std::string& path, const uint64_t fileHandle);
private:
    SubjectInfo(const std::string& path, const uint64_t fileHandle);
    std::expected<const std::vector<char>, std::string_view> getFileUuid();
};
