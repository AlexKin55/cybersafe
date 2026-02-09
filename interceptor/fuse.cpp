#include <cstring>

#include "fuse.hpp"
#include <fcntl.h>
#include <unistd.h>

#include <utime.h>
#include <sys/stat.h>

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
std::filesystem::path SecureFileSystem::m_sourceRoot = "";

SubjectInfo SecureFileSystem::GetCurrentSubject() {
    auto ctx = fuse_get_context();
    return SubjectInfo{
        .uid = ctx->uid,
        .gid = ctx->gid,
        .pid = ctx->pid
    };
}

SecureFileSystem::SecureFileSystem(std::unique_ptr<IInterceptor> interceptor,
    std::filesystem::path& root) {

    m_interceptor = std::move(interceptor);
    m_sourceRoot = root;
}

int SecureFileSystem::Create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    std::filesystem::path fullPath = m_sourceRoot / (path + 1);

    int fd = open(fullPath.c_str(), fi->flags, mode);
    if (fd == -1) {
        return -errno;
    }

    fi->fh = fd;
    return 0; 
}

int SecureFileSystem::Mknod(const char *path, mode_t mode, dev_t rdev) {
    std::filesystem::path fullPath = m_sourceRoot / (path + 1);

    int res;
    if (S_ISREG(mode)) {
        res = open(fullPath.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode)) {
        res = mkfifo(fullPath.c_str(), mode);
    } else {
        res = mknod(fullPath.c_str(), mode, rdev);
    }

    if (res == -1) {
        return -errno;
    }

    return 0;
}

int SecureFileSystem::Release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    return 0;
}

int SecureFileSystem::GetAttr(const char* path, struct stat* stbuf,
    struct fuse_file_info* fi) {
    std::filesystem::path fullPath = m_sourceRoot / (path + 1);

    if (int res = lstat(fullPath.c_str(), stbuf); res == -1) {
        return -errno;
    }
    return 0;
}

int SecureFileSystem::SetAttr(const char *path, struct stat *attr, int mask) {
    std::filesystem::path fullPath = m_sourceRoot / (path + 1);

    if (mask & FUSE_SET_ATTR_SIZE) {
        if (int res = truncate(fullPath.c_str(), attr->st_size); res == -1) {
            return -errno;
        }
    }

    if (mask & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
        if (int res = lchown(fullPath.c_str(), (mask & FUSE_SET_ATTR_UID) ? attr->st_uid : -1,
                (mask & FUSE_SET_ATTR_GID) ? attr->st_gid : -1); res == -1) {
            return -errno;
        }
    }

    if (mask & FUSE_SET_ATTR_MODE) {
        if (int res = chmod(fullPath.c_str(), attr->st_mode); res == -1) {
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
            return -errno;
        }
    }

    return 0;
}

int SecureFileSystem::Truncate(const char *path, off_t size) {
    std::filesystem::path fullPath = m_sourceRoot / (path + 1);

    if (int res = truncate(fullPath.c_str(), size); res == -1) {
        return -errno;
    }

    return 0;
}

int SecureFileSystem::Open(const char* path, struct fuse_file_info* fi) {
    std::filesystem::path fullPath = m_sourceRoot / (path + 1);

    fi->direct_io = 1;
    int fd = ::open(fullPath.c_str(), fi->flags);
    if (fd == -1) {
        return -errno;
    }

    fi->fh = fd;
    return 0;
}

int SecureFileSystem::Read(const char* path, char* buf, size_t size, off_t offset,
    struct fuse_file_info* fi) {
    int res = pread(fi->fh, buf, size, offset);
    if (res == -1) {
        return -errno;
    }
    return res;
}

int SecureFileSystem::Write(const char* path, const char* buf, size_t size, off_t offset,
    struct fuse_file_info* fi) {
    auto subject = GetCurrentSubject();
    
    {
        std::shared_lock<std::shared_mutex> lock(SecureFileSystem::m_mutex);
        if (!m_interceptor->Permit(path, W_OK, subject)) {
            //return -EACCES;
        }
    }

    std::vector<char> encryptedBuffer(buf, buf + size);

    std::span<char> modifiedData(const_cast<char*>(buf), size);
    m_interceptor->TransformData(path, encryptedBuffer, offset);

    int res = pwrite(fi->fh, encryptedBuffer.data(), size, offset);
    if (res == -1) {
        return -errno;
    }
    return res;
}

int SecureFileSystem::ReadDir(const char *path, void *buf, fuse_fill_dir_t filler,
                              off_t offset, struct fuse_file_info *fi,
                              enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    filler(buf, ".", NULL, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", NULL, 0, (fuse_fill_dir_flags)0);

    std::filesystem::path fullPath = m_sourceRoot / (path + 1);

    try {
        for (const auto& entry : std::filesystem::directory_iterator(fullPath)) {
            // Передаем имя файла из реальной папки в FUSE
            std::string name = entry.path().filename().string();
            if (filler(buf, name.c_str(), NULL, 0, (fuse_fill_dir_flags)0))
                break;
        }
    } catch (const std::exception& e) {
        return -ENOENT;
    }

    return 0;
}

void SecureFileSystem::UpdateRules(std::unique_ptr<IInterceptor> new_interceptor) {
    std::unique_lock<std::shared_mutex> lock(SecureFileSystem::m_mutex);
    m_interceptor = std::move(new_interceptor);
}

const struct fuse_operations* SecureFileSystem::GetOps() {
    static struct fuse_operations ops = {};
    ops.getattr = SecureFileSystem::GetAttr;
    ops.open    = SecureFileSystem::Open;
    ops.read    = SecureFileSystem::Read;
    ops.write   = SecureFileSystem::Write;
    ops.create  = SecureFileSystem::Create;
    ops.mknod   = SecureFileSystem::Mknod;
    ops.release = SecureFileSystem::Release;
    ops.readdir = SecureFileSystem::ReadDir;
    return &ops;
}

// sudo setcap cap_sys_ptrace=ep ./my_fuse_agent для чтения PIDов других пользователей