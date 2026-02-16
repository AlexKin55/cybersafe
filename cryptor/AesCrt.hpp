#pragma once
#include "icryptor.hpp"

class AesCtrCryptor : public ICryptor {
public:

    AesCtrCryptor(std::unique_ptr<IKeyGetter> keyGetter) : m_keyGetter(std::move(keyGetter)) {
    };

    std::expected<std::vector<char>, std::string_view>
        Encrypt(const SubjectInfo& subjectInfo, std::span<char> data, off_t offset) override;
    
    std::expected<std::vector<char>, std::string_view>
        Decrypt(const SubjectInfo& subjectInfo, std::span<char> data, off_t offset) override;

private:
    std::expected<std::vector<char>, std::string_view>
        Process(const SubjectInfo& subjectInfo, std::span<char> data, off_t offset);

    std::unique_ptr<IKeyGetter> m_keyGetter;
};

