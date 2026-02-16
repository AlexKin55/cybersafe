#define FUSE_USE_VERSION 31

#include "subjectInfo.hpp"
#include <cstring>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <unistd.h>
#include <uuid/uuid.h>

namespace {

    std::vector<char> getUuidFromHeader(const CyberHead& head) {
        if (head.magicBytes != MAGIC_BYTES) {
            return {};
        }
        return std::vector<char>(head.uuid, head.uuid + sizeof(CyberHead::uuid));
    }

    const CyberHead makeCyberHead() {
        CyberHead header{};
        std::memcpy(header.magicBytes, MAGIC_BYTES.data(), MAGIC_BYTES.size());
        std::memcpy(header.agentVersion, AGENT_VERSION.data(), AGENT_VERSION.size());
        uuid_generate(reinterpret_cast<unsigned char*>(header.uuid));

        return header;
    }
}

SubjectInfo::SubjectInfo(const std::string& path, const uint64_t fileHandle) : m_fileName(path), m_fileHandle(fileHandle) {
    auto ctx = fuse_get_context();
    m_uid = ctx->uid;
    m_gid = ctx->gid;
    m_pid = ctx->pid;
}

std::expected<const std::vector<char>, std::string_view> SubjectInfo::getFileUuid() {
    if (!m_uuid.empty()) {
        return m_uuid;
    }

    CyberHead head{};
    int res = pread(m_fileHandle, &head, sizeof(CyberHead), 0);
    if (res == -1) {
        return std::unexpected("Couldn't read cybersafe header from file"sv);
    }

    if (res < sizeof(CyberHead)) {
        head = makeCyberHead();
    }

    auto uuid = getUuidFromHeader(head);
    if (uuid.empty()) {
        return std::unexpected("Bad Cybersafe Magic bytes"sv);
    }

    m_uuid = std::move(uuid);
    return m_uuid;
}

std::expected<void, std::string_view> SubjectInfo::writeCyberHeader() {
    auto head = makeCyberHead();

    int res = pwrite(m_fileHandle, &head, sizeof(CyberHead), 0);
    if (res == -1 || res != sizeof(CyberHead)) {
        return std::unexpected("Couldn't write Cybersafe Magic bytes"sv);
    }

    return {};
}

std::expected<const struct SubjectInfo, std::string_view>
MakeSubjectInfo(const std::string& path, const uint64_t fileHandle) {

    auto subjectInfo = SubjectInfo(path, fileHandle);
    if (auto res = subjectInfo.getFileUuid(); !res) {
        return std::unexpected(res.error());
    }
    return subjectInfo;
}