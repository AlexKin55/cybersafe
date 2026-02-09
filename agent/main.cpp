#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include "fuse.hpp"
#include "interceptor.hpp"

static constexpr const char* optFlag = "-o";
static constexpr const char* optValue = "allow_other";

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
public:
    Interceptor() = default;

    bool Permit(const std::string& path, int mask, const SubjectInfo& subject) const override {
        // Rule 1: Always allow Root
        //if (subject.uid == 0) {
        //    return true;
        //}

        if (IsInFirejail(subject.pid)) {
            // Процесс защищен песочницей, разрешаем доступ
            return true;
        }

        return false;
    }

    void LogAccess(const std::string& path, const SubjectInfo& subject, bool allowed) const override {
        if (!allowed) {
            std::cout << "[SECURITY] Access DENIED for PID: " << subject.pid 
                      << " attempting to access: " << path << std::endl;
        } else {
            std::cout << "[SECURITY] Access GRANTED for PID: " << subject.pid << std::endl;
        }
    }

    void TransformData(const std::string& path, std::span<char> data, off_t offset) const override {
    
    }

};

template <typename F>
struct ScopeGuard {
    F func;
    ~ScopeGuard() { func(); }
};

int main(int argc, char* argv[]) {
    // Basic usage check
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <source_directory> <mount_point> [fuse_options]" << std::endl;
        std::cerr << "Example: " << argv[0] << " /home/user/data /tmp/secure_zone -f" << std::endl;
        return 1;
    }

    ScopeGuard cleanup{[&] {
        std::cout << "Cleaning up FUSE..." << std::endl;
        std::string str = "fusermount3 -u " + std::string(argv[2]);
        system(str.c_str());
    }};

    try {
        auto interceptor = std::make_unique<Interceptor>();

        std::filesystem::path sourcePath = std::filesystem::absolute(argv[1]);
        
        if (!std::filesystem::exists(sourcePath)) {
            std::cerr << "Error: Source directory does not exist: " << sourcePath << std::endl;
            return 1;
        }

        std::cout << "Starting SecureFS..." << std::endl;
        std::cout << "Mirroring: " << sourcePath << " to " << argv[2] << std::endl;

        // SecureFileSystem constructor stores the interceptor and root path globally
        SecureFileSystem fs_manager(std::move(interceptor), sourcePath);

        // 3. Hand over control to libfuse
        // We skip argv[1] (source_dir) because fuse_main expects: [binary, mountpoint, ...options]
        // So we shift the arguments
        std::vector<char*> fuseArgv;
        fuseArgv.emplace_back(argv[1]);      // Binary name
        for (int i = 2; i < argc; ++i) {
            fuseArgv.emplace_back(argv[i]);  // Mount point and FUSE flags (-f, -d, etc)
        }

        //fuseArgv.push_back(const_cast<char*>(optFlag));
        //fuseArgv.push_back(const_cast<char*>(optValue));

        return fuse_main(static_cast<int>(fuseArgv.size()), fuseArgv.data(), SecureFileSystem::GetOps(), nullptr);

    } catch (const std::exception& e) {
        std::cerr << "Fatal Error: " << e.what() << std::endl;
        return 1;
    }
}
