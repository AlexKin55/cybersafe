#include <iostream>
#include <format>
#include <fstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>
#include <algorithm>

#include "fuse.hpp"
#include "settings.hpp"
#include "AesCrt.hpp"
#include "keyGetterFromFile.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>

bool IsInFirejail(pid_t pid) {
    std::string envPath = "/proc/" + std::to_string(pid) + "/environ";
    
    std::ifstream envFile(envPath, std::ios::binary);
    if (!envFile.is_open()) {
        return false;
    }

    std::string buffer;
    while (std::getline(envFile, buffer, '\0')) {
        if (buffer == "FIREJAIL_SANDBOX=yes") {
            return true;
        }
    }

    return false;
}

// A concrete Interceptor that only allows specific PIDs or the Root user
class Interceptor : public IInterceptor {

    std::unique_ptr<ICryptor> m_cryptor;
    std::unordered_map<std::string, std::unique_ptr<const struct SubjectInfo>> m_context;

public:
    Interceptor(std::unique_ptr<ICryptor> cryptor) : m_cryptor(std::move(cryptor)){
    };

    virtual ~Interceptor() override = default;


    bool Permit(int mask, const SubjectInfo& subject) const override {
        // Rule 1: Always allow Root
        //if (subject.uid == 0) {
        //    return true;
        //}

        bool isFireJail = IsInFirejail(subject.m_pid);
        spdlog::info("permit isFireJile: {} PID: {}", isFireJail, subject.m_pid);

        if (isFireJail) {
            return true;
        }

        return false;
    }

    void LogAccess(const SubjectInfo& subject, bool allowed) const override {
        if (!allowed) {
            spdlog::info("[SECURITY] Access DENIED for PID: {} attempting to access: {}"
                , subject.m_pid, subject.m_fileName);
        } else {
            spdlog::info("[SECURITY] Access GRANTED for PID: {}", subject.m_pid);
        }
    }

    uint64_t Write(const SubjectInfo& subject, std::span<char> data, off_t offset) override {
    
        /*
        auto it = m_context.find(path);
        if (it == m_context.end()) {
            it = m_context.emplace(path, Context{path, std::string("alex")});
        }
        */

        spdlog::info("write PID: {}", subject.m_pid);

        return 0;
    }

    uint64_t Read(const SubjectInfo& subject, std::vector<char>& data, off_t offset) override {
    
        spdlog::info("read PID: {}", subject.m_pid);
        return 0;
    }
};

std::expected<std::tuple<std::filesystem::path, std::filesystem::path, std::vector<std::string>>, std::string>
    getBasicSettings(const Settings& settings) {

    std::filesystem::path sourceDir;
    if (auto res = settings.getParam("fuse.directory"); res) {
        sourceDir = std::filesystem::absolute(res.value());
        if (!std::filesystem::exists(sourceDir)) {
            return std::unexpected(std::format("Error: invalid source directory: {}", sourceDir.generic_string()));
        }
    }

    std::filesystem::path mountPoint;
    if (auto res = settings.getParam("fuse.mount_point"); res) {
        mountPoint = std::filesystem::absolute(res.value());
        if (!std::filesystem::exists(mountPoint)) {
            return std::unexpected(std::format("Error: invalid mount point: {}", mountPoint.generic_string()));
        }
    }

    std::vector<std::string> fuseOptions;
    if (auto res = settings.getParamAsVector("fuse.options"); res) {
        fuseOptions = res.value();
    }
    return std::make_tuple(sourceDir, mountPoint, fuseOptions);
}

std::expected<std::tuple<std::filesystem::path, std::string, std::string, uint64_t, int>, std::string>
    getLoggerSettings(const Settings& settings) {

    std::filesystem::path logFile;
    if (auto res = settings.getParam("log.file"); res) {
        logFile = std::filesystem::absolute(res.value());
    }
    std::string level;
    if (auto res = settings.getParam("log.level"); res) {
        level = res.value();
    }

    std::string flush_level;
    if (auto res = settings.getParam("log.flush_level"); res) {
        flush_level = res.value();
    }

    /*
        std::ofstream file(logFile); 
        if (!file.is_open()) {
            return std::unexpected(std::format("Error: invalid log file: {}", logFile.generic_string()));
        }
        file.close();
    }
    */

    uint64_t logFileSize = 5*1024*1024;
    int logFileCount = 3;

    return std::make_tuple(logFile, level, flush_level, logFileSize, logFileCount);
}

bool initLogger(const Settings& settings) {
    
    const auto logRes = getLoggerSettings(settings);
    if (!logRes) {
        std::cerr << logRes.error() << std::endl;
        return 1;
    }

    auto [logFile, logLevel, flush_logLevel, logFileSize, logFileCount] = logRes.value();
    try {
        auto fileLogger = spdlog::rotating_logger_mt("agent_logger",
            logFile.string().c_str(), logFileSize, logFileCount);
        spdlog::set_default_logger(fileLogger);
        spdlog::set_level(spdlog::level::from_str(logLevel)); 
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v");
        spdlog::flush_on(spdlog::level::from_str(flush_logLevel));
        
    } catch (const spdlog::spdlog_ex &e) {
        std::cerr << "Log initialization failed: " << e.what() << std::endl;
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {

    if (argc == 1) {
        std::cerr << "Usage: " << argv[0] << " <settings_file>" << std::endl;
        std::cerr << "Example: " << argv[0] << "settings.yaml" << std::endl;
        return 1;
    }

    const auto settingsFile = std::filesystem::absolute(argv[1]);
    if (!std::filesystem::exists(settingsFile)) {
        std::cerr << std::format("Settings file does not exist: {}", settingsFile.generic_string()) << std::endl;
        return 1;
    }

    Settings settings(settingsFile.generic_string());
    if (!settings.isValid()) {
        std::cerr << "Settings parameters are invalid" << std::endl;
        return 1;
    }

    if (!initLogger(settings)) {
        std::cerr << "Could'n initialize logger" << std::endl;
        return 1;
    }
    /*
    if (auto res = settings.getParam("log.fuse"); res) {
        const auto fuseLogFile = std::filesystem::absolute(res.value());
        if (std::freopen(fuseLogFile.generic_string().c_str(), "w", stdout)) {
            std::setvbuf(stdout, nullptr, _IONBF, 0);
        }
    }
    */

    const auto settingsRes = getBasicSettings(settings);
    if (!settingsRes) {
        spdlog::error("{}", settingsRes.error());
        return 1;
    }
    auto [sourceDir, mountPoint, fuseOptions] = settingsRes.value();
    const std::string sPath = sourceDir.string();
    const std::string mPath = mountPoint.string();

    auto keyGetter = std::make_unique<KeyGetterFromFile>();
    auto aesCrtCryptor = std::make_unique<AesCtrCryptor>(std::move(keyGetter));
    auto interceptor = std::make_unique<Interceptor>(std::move(aesCrtCryptor));

    spdlog::info("Starting CyberSafe ...");
    spdlog::info("Mirroring: {} to {}", sPath, mPath);

    SecureFileSystem fsManager(std::move(interceptor), sourceDir);

    std::vector<char*> fuseArgv;
    fuseArgv.reserve(fuseOptions.size() + 1);
    for (auto& s : fuseOptions) {
        fuseArgv.push_back(s.data());
    }
    fuseArgv.push_back(const_cast<char*>(mPath.c_str()));

    return fuse_main(static_cast<int>(fuseArgv.size()), fuseArgv.data(), SecureFileSystem::GetOps(), nullptr);
}
