#include "keyGetterFromFile.hpp"
#include <cstring>
#include <stdexcept>
#include <vector>
#include <expected>
#include <span>

using namespace std::string_view_literals;

void KeyGetterFromFile::LoadKey(const SubjectInfo& subjectInfo, std::span<char> key) {
    return;
}

std::expected<std::vector<char>, std::string_view> KeyGetterFromFile::GetKey(const SubjectInfo& subjectInfo) {

    const auto& uuid = subjectInfo.m_uuid;
    if (const auto& it = m_context.find(uuid); it != m_context.end()) {
        return it->second;
    }

    std::vector<char> key;
    // to do open key files and get key

    return key;
}