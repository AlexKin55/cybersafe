#pragma once
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <filesystem>
#include "interceptor.hpp"

class SecureFileSystem {
public:
    explicit SecureFileSystem(std::unique_ptr<IInterceptor> interceptor, std::filesystem::path& root);

    static int Create(const char *path, mode_t mode, struct fuse_file_info *fi);
    static int Mknod(const char *path, mode_t mode, dev_t rdev) ;
    static int Release(const char *path, struct fuse_file_info *fi);
    static int GetAttr(const char* path, struct stat* stbuf, struct fuse_file_info* fi);
    static int Open(const char* path, struct fuse_file_info* fi);
    static int Read(const char* path, char* buf, size_t size, off_t offset,
        struct fuse_file_info* fi);
    static int Write(const char* path, const char* buf, size_t size, off_t offset,
        struct fuse_file_info* fi);
    static int SetAttr(const char *path, struct stat *attr, int mask);
    static int Truncate(const char *path, off_t size);
    static int ReadDir(const char *path, void *buf, fuse_fill_dir_t filler,
        off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);
    static const struct fuse_operations* GetOps();

    void UpdateRules(std::unique_ptr<IInterceptor> newInterceptor);

private:
    static std::shared_mutex m_mutex;
    // Вспомогательный метод для конвертации контекста
    static SubjectInfo GetCurrentSubject();

    static std::unique_ptr<IInterceptor> m_interceptor;
    static std::filesystem::path m_sourceRoot;
};
