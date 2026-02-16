#include <cstring>

#include "fuse.hpp"
#include <fcntl.h>
#include <unistd.h>

#include <utime.h>
#include <uuid/uuid.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>

#ifndef FUSE_SET_ATTR_MODE
#define FUSE_SET_ATTR_MODE  (1 << 0)
#define FUSE_SET_ATTR_UID   (1 << 1)
#define FUSE_SET_ATTR_GID   (1 << 2)
#define FUSE_SET_ATTR_SIZE  (1 << 3)
#define FUSE_SET_ATTR_ATIME (1 << 4)
#define FUSE_SET_ATTR_MTIME (1 << 5)
#endif

std::shared_mutex SecureFileSystem::m_mutex;
std::unique_ptr<IInterceptor> SecureFileSystem::m_interceptor = nullptr;
std::string SecureFileSystem::m_sourceRoot = "";
std::unordered_map<uint64_t, const SubjectInfo> SecureFileSystem::m_cache;

namespace {

    std::string errnoToString(int err) {
        return std::string(std::strerror(err));
    }

    const std::string uuidToString(const std::vector<char> uuid) {
        char uuid_str[37];
        uuid_unparse(reinterpret_cast<const unsigned char*>(uuid.data()), uuid_str);
        return std::string(uuid_str);
    }
}


SecureFileSystem::SecureFileSystem(std::unique_ptr<IInterceptor> interceptor,
    std::filesystem::path& root) {

    m_interceptor = std::move(interceptor);
    m_sourceRoot = root.generic_string();
}

int SecureFileSystem::Create(const char *path, mode_t mode, struct fuse_file_info *fi) {

    const auto filePath = std::string(path);
    const auto fullPath = m_sourceRoot + filePath;

    spdlog::debug("create file {}", filePath);

    int fd = open(fullPath.c_str(), fi->flags, mode);
    if (fd == -1) {
        spdlog::error("open file {} failed error {}", filePath, errnoToString(errno));
        return -errno;
    }

    fi->fh = fd;

    const auto res = SecureFileSystem::GetCurrentSubject(filePath, fi->fh);
    if (!res) {
        spdlog::error("couldn't get subject for file {}, error {}", filePath, res.error());
        return -errno;
    }

    const auto subject = res.value();
    spdlog::debug("created file {}, fd {}, uuid {}"
        , subject.m_fileName, subject.m_fileHandle, uuidToString(subject.m_uuid));
    return 0; 
}

int SecureFileSystem::Mknod(const char *path, mode_t mode, dev_t rdev) {

    const auto filePath = std::string(path);

    spdlog::debug("make node {}, mode {}", filePath, mode);

    const auto fullPath = m_sourceRoot + filePath;
    int fd;
    int res;
    if (S_ISREG(mode)) {
        fd = open(fullPath.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
        if (fd >= 0) {
            res = close(fd);
        }
    } else if (S_ISFIFO(mode)) {
        fd = mkfifo(fullPath.c_str(), mode);
    } else {
        fd = mknod(fullPath.c_str(), mode, rdev);
    }

    return 0;
}

int SecureFileSystem::Release(const char *path, struct fuse_file_info *fi) {

    const auto filePath = std::string(path);
    const auto res = SecureFileSystem::GetCurrentSubject(filePath, fi->fh);
    if (!res) {
        spdlog::error("couldn't get subject for file {}, error {}", filePath, res.error());
    }

    const auto subject = res.value();
    spdlog::debug("mknod file {}, fd {}, uuid {}"
        , subject.m_fileName, subject.m_fileHandle, uuidToString(subject.m_uuid));

    DeleteCurrentSubject(fi->fh);
    close(fi->fh);
    return 0;
}

int SecureFileSystem::GetAttr(const char* path, struct stat* stbuf, struct fuse_file_info* fi) {

    const auto filePath = std::string(path);
    const auto fullPath = m_sourceRoot + filePath;

    spdlog::debug("getaddr file {}", filePath);

    if (int res = lstat(fullPath.c_str(), stbuf); res == -1) {
        spdlog::error("lstat file {} failed error {}", filePath, errnoToString(errno));
        return -errno;
    }
    return 0;
}

int SecureFileSystem::GetXattr(const char *path, const char *name, char *value, size_t size) {

    const auto filePath = std::string(path);
    const auto fullPath = m_sourceRoot + filePath;

    spdlog::debug("getxaddr file {}", filePath);

    int res = lgetxattr(fullPath.c_str(), name, value, size);
    if (res == -1) {
        spdlog::error("lgetxattr file {} failed error {}", filePath, errnoToString(errno));
        return -errno;
    }
    return res;
}

int SecureFileSystem::SetAttr(const char *path, struct stat *attr, int mask) {

    const auto filePath = std::string(path);

    spdlog::debug("setaddr file {}", filePath);

    const auto fullPath = m_sourceRoot + filePath;

    if (mask & FUSE_SET_ATTR_SIZE) {
        if (int res = truncate(fullPath.c_str(), attr->st_size); res == -1) {
            spdlog::error("truncate file {} failed error {}", filePath, errnoToString(errno));
            return -errno;
        }
    }

    if (mask & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
        if (int res = lchown(fullPath.c_str(), (mask & FUSE_SET_ATTR_UID) ? attr->st_uid : -1,
                (mask & FUSE_SET_ATTR_GID) ? attr->st_gid : -1); res == -1) {
            spdlog::error("lchown file {} failed error {}", filePath, errnoToString(errno));
            return -errno;
        }
    }

    if (mask & FUSE_SET_ATTR_MODE) {
        if (int res = chmod(fullPath.c_str(), attr->st_mode); res == -1) {
            spdlog::error("chmod file {} failed error {}", filePath, errnoToString(errno));
            return -errno;
        }
    }

    if (mask & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
        struct utimbuf tv;
        struct stat st;
        lstat(fullPath.c_str(), &st);
        tv.actime = (mask & FUSE_SET_ATTR_ATIME) ? attr->st_atime : st.st_atime;
        tv.modtime = (mask & FUSE_SET_ATTR_MTIME) ? attr->st_mtime : st.st_mtime;
        if (int res = utime(fullPath.c_str(), &tv); res == -1) {
            spdlog::error("utime file {} failed error {}", filePath, errnoToString(errno));
            return -errno;
        }
    }

    return 0;
}

int SecureFileSystem::Truncate(const char *path, off_t size) {

    const auto filePath = std::string(path);

    spdlog::debug("truncate file {}", filePath);

    const auto fullPath = m_sourceRoot + filePath;

    if (int res = truncate(fullPath.c_str(), size); res == -1) {
        spdlog::error("truncate file {} failed error {}", filePath, errnoToString(errno));
        return -errno;
    }

    return 0;
}

int SecureFileSystem::Open(const char* path, struct fuse_file_info* fi) {

    const auto filePath = std::string(path);

    spdlog::debug("open file {}", filePath);

    int flags = fi->flags;
    if ((flags & O_ACCMODE) == O_WRONLY) {
        flags &= ~O_ACCMODE;
        flags |= O_RDWR;
    }

    fi->direct_io = 1;
    const auto fullPath = m_sourceRoot + filePath;
    int fd = ::open(fullPath.c_str(), flags);
    if (fd == -1) {
        spdlog::error("open file {} failed error {}", filePath, errnoToString(errno));
        return -errno;
    }

    fi->fh = fd;
    return 0;
}

int SecureFileSystem::Read(const char* path, char* buf, size_t size, off_t offset,
    struct fuse_file_info* fi) {

    const auto filePath = std::string(path);
    spdlog::debug("read file {}", filePath);

    if (int res = pread(fi->fh, buf, size, offset); res == -1) {
        spdlog::error("pread file {} failed error {}", filePath, errnoToString(errno));
        return -errno;
    }

    auto subjectRes = MakeSubjectInfo(filePath, fi->fh);
    if (!subjectRes) {
        spdlog::error("couldn't make subjectInfo for file {}, {}, errno {}"
            , filePath, subjectRes.error(), errno);
        return -errno;
    }

    const auto subject = subjectRes.value();
    {
        std::shared_lock<std::shared_mutex> lock(SecureFileSystem::m_mutex);
        if (!m_interceptor->Permit(W_OK, subject)) {
            spdlog::info("not permit for file {}", filePath);
            //return -EACCES;
        }
    }

    std::vector<char> data(size);
    const auto rBytes = m_interceptor->Read(subject, data, offset);
    if (rBytes > size) {
        spdlog::error("read file {} failed, error {}", filePath, errno);
        return -errno;
    }

    data.resize(rBytes);
    std::copy(data.begin(), data.end(), buf);

    return rBytes;
}

void SecureFileSystem::DeleteCurrentSubject(uint64_t fh) {
    std::unique_lock<std::shared_mutex> lock(SecureFileSystem::m_mutex);
    m_cache.erase(fh);
}

std::expected<const SubjectInfo, int> SecureFileSystem::GetCurrentSubject(const std::string& path, uint64_t fh) {

    {
        std::shared_lock<std::shared_mutex> lock(SecureFileSystem::m_mutex);
        if (const auto& it = m_cache.find(fh); it != m_cache.end()) {
            return it->second;
        }
    }

    const auto subjectRes = MakeSubjectInfo(path, fh);
    if (!subjectRes) {
        spdlog::error("coundn't make subjectInfo for file {} {}, errno {}"
            , path, subjectRes.error(), errno);
        return std::unexpected(-errno);
    }

    std::unique_lock<std::shared_mutex> lock(SecureFileSystem::m_mutex);
    m_cache.emplace(fh, subjectRes.value());
    return subjectRes.value();
}

int SecureFileSystem::Write(const char* path, const char* buf, size_t size, off_t offset,
    struct fuse_file_info* fi) {
    
    const auto filePath = std::string(path);
    spdlog::debug("write file {}", filePath);

    auto subjectRes = MakeSubjectInfo(filePath, fi->fh);
    if (!subjectRes) {
        spdlog::error("coundn't make subjectInfo for file {} {}, errno {}"
            , filePath, subjectRes.error(), errno);
        return -errno;
    }
    const auto subject = subjectRes.value();
    {
        std::shared_lock<std::shared_mutex> lock(SecureFileSystem::m_mutex);
        if (!m_interceptor->Permit(W_OK, subject)) {
            spdlog::info("not permit for file {} failed", filePath);
            //return -EACCES;
        }
    }

    std::vector<char> data(buf, buf + size);
    m_interceptor->Write(subject, data, offset);

    int res = pwrite(fi->fh, data.data(), size, offset);
    if (res == -1) {
        spdlog::error("pwrite failed for file {}, error {}", filePath, errnoToString(errno));
        return -errno;
    }
    return res;
}

int SecureFileSystem::Flush(const char *path, struct fuse_file_info *fi) {

    const auto filePath = std::string(path);
    spdlog::debug("flush file {}", filePath);
    return 0;
}

int SecureFileSystem::ReadDir(const char *path, void *buf, fuse_fill_dir_t filler,
                              off_t offset, struct fuse_file_info *fi,
                              enum fuse_readdir_flags flags) {
    const auto filePath = std::string(path);
    spdlog::debug("readdir file {}", filePath);

    (void) offset;
    (void) fi;
    (void) flags;

    filler(buf, ".", NULL, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", NULL, 0, (fuse_fill_dir_flags)0);

    const auto fullPath = m_sourceRoot + filePath;

    try {
        for (const auto& entry : std::filesystem::directory_iterator(fullPath)) {
            std::string name = entry.path().filename().string();
            if (filler(buf, name.c_str(), NULL, 0, (fuse_fill_dir_flags)0)) {
                break;
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("coundn't iterate in directory {} error {}", filePath, e.what());
        return -ENOENT;
    }

    return 0;
}

void SecureFileSystem::UpdateRules(std::unique_ptr<IInterceptor> new_interceptor) {
    spdlog::info("UpdateRules");
    std::unique_lock<std::shared_mutex> lock(SecureFileSystem::m_mutex);
    m_interceptor = std::move(new_interceptor);
}

const struct fuse_operations* SecureFileSystem::GetOps() {

    spdlog::debug("Registrate FUSE callback for root {}", m_sourceRoot);

    static struct fuse_operations ops = {};
    ops.getattr = SecureFileSystem::GetAttr;
    ops.open    = SecureFileSystem::Open;
    ops.read    = SecureFileSystem::Read;
    ops.write   = SecureFileSystem::Write;
    ops.create  = SecureFileSystem::Create;
    ops.mknod   = SecureFileSystem::Mknod;
    ops.release = SecureFileSystem::Release;
    ops.readdir = SecureFileSystem::ReadDir;
    ops.getxattr = SecureFileSystem::GetXattr;
    ops.flush   = SecureFileSystem::Flush;
    return &ops;
}

// sudo setcap cap_sys_ptrace=ep ./my_fuse_agent для чтения PIDов других пользователей