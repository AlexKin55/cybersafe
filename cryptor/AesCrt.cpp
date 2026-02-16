#include "AesCrt.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <expected>
#include <span>

using namespace std::string_view_literals;

std::expected<std::vector<char>, std::string_view> 
AesCtrCryptor::Encrypt(const SubjectInfo& subjectInfo, std::span<char> data, off_t offset) {
    return Process(subjectInfo, data, offset);
}

std::expected<std::vector<char>, std::string_view>
AesCtrCryptor::Decrypt(const SubjectInfo& subjectInfo, std::span<char> data, off_t offset) {
    return Process(subjectInfo, data, offset);
}

std::expected<std::vector<char>, std::string_view>
AesCtrCryptor::Process(const SubjectInfo& subjectInfo, std::span<char> data, off_t offset) {
    
    auto res = m_keyGetter->GetKey(subjectInfo); 
    if (!res) { 
        return std::unexpected(res.error());
    }

    const auto key = res.value();
    if (key.size() < 32) { 
        return std::unexpected("Key too short"sv);
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> 
        ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!ctx) {
        return std::unexpected("Failed to create EVP context"sv);
    }

    unsigned char iv[16] = {0};
    uint64_t blockIndex = static_cast<uint64_t>(offset) / 16;
    uint64_t byteInBlock = static_cast<uint64_t>(offset) % 16;
    for (int i = 15; i >= 8; i--) {
        iv[i] = static_cast<unsigned char>(blockIndex & 0xFF);
        blockIndex >>= 8;
    }

    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr, 
            reinterpret_cast<const unsigned char*>(key.data()), iv)) {
        return std::unexpected("Init failed"sv);
    }

    if (byteInBlock > 0) {
        unsigned char dummyIn[16] = {0};
        unsigned char dummyOut[16];
        int len;
        EVP_EncryptUpdate(ctx.get(), dummyOut, &len, dummyIn, static_cast<int>(byteInBlock));
    }

    std::vector<char> outData;
    outData.reserve(data.size());

    int outLen;
    if (1 != EVP_EncryptUpdate(ctx.get(), 
            reinterpret_cast<unsigned char*>(outData.data()), &outLen,
            reinterpret_cast<const unsigned char*>(data.data()), 
            static_cast<int>(data.size()))) {
        return std::unexpected("Update failed"sv);
    }

    return outData;
}

