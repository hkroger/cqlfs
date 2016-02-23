#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <mutex>
#include <map>
#include <string>


#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION  26
#include <osxfuse/fuse/fuse.h>

#include "cqlfs_common.h"
#include "CassandraFS.h"
#include "FileBlockCache.h"

#define not_implemented(x...) debug("not implemented: " x);return -ENOSYS;

CassandraContext* cassandraCtxt;
CassandraFS* cassandraFS;

class StatCache : public Cache {
public:
    struct stat stat;
    CassUuid physical_file_id;
};

class FileCache : public Cache {

public:
    FileCache();
    struct cfs_attrs cfs;
    CassandraFutureSpool spool;
};

FileCache::FileCache(): spool(16) {

}

// Key uuid
std::map<std::string, FileCache*> cfs_stat_cache;

// Key path
std::map<std::string, StatCache*> stat_cache;

std::mutex cache_mutex;

void establish_cache(const char* path) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    struct cfs_attrs cfs;
    int cfs_loaded = 0;
    CassUuid physical_file_id;

    // Initialize stat cache
    if (stat_cache.count(path)>0) {
        stat_cache[path]->inc_user_count();
        physical_file_id = stat_cache[path]->physical_file_id;
    } else {
        StatCache *cache_item = new StatCache();
        cfs_loaded = 1;
        cassandraFS->getattr(path, &(cache_item->stat), &cfs);
        cache_item->physical_file_id = cfs.physical_file_id;
        physical_file_id = cfs.physical_file_id;
        cache_item->set_user_count(1);
        stat_cache[path] = cache_item;
    }

    char uuid_string[CASS_UUID_STRING_LENGTH];
    cass_uuid_string(physical_file_id, uuid_string);
    
    // Initialize FileCache
    if (cfs_stat_cache.count(uuid_string)>0) {
        cfs_stat_cache[uuid_string]->inc_user_count();
    } else {
        FileCache *cache_item = new FileCache();
        if (cfs_loaded) {
            cache_item->cfs = cfs;
        } else {
            // This is an edge case, should not even happen
            warning("Initializing CFS cache but CFS stats were not loaded. Path: %s, FileID: %s", path, uuid_string);
            struct stat stat;
            cassandraFS->getattr(path, &stat, &(cache_item->cfs));
        }
        cache_item->set_user_count(1);
        cfs_stat_cache[uuid_string] = cache_item;
    }
}

void release_cache(const char* path) {
    std::lock_guard<std::mutex> lock(cache_mutex);

    StatCache* stat_item = stat_cache.at(path);
    
    char uuid_string[CASS_UUID_STRING_LENGTH];
    cass_uuid_string(stat_item->physical_file_id, uuid_string);

    if (cfs_stat_cache.count(uuid_string)>0) {
        FileCache* item = cfs_stat_cache[uuid_string];
        
        item->dec_user_count();
        
        if (item->user_count()<=0) {
            cfs_stat_cache.erase(uuid_string);
        }
    } else {
        warning("Path %s was not found cfs stat cache to be released with uuid: %s", path, uuid_string);
    }
    
    if (stat_cache.count(path)>0) {
        StatCache* item = stat_cache[path];
        
        item->dec_user_count();
        
        if (item->user_count()<=0) {
            stat_cache.erase(path);
        }
    } else {
        warning("Path %s was not found stat cache to be release", path);
    }
}

int cql_access(const char* path, int mask) {
    //debug("access: %s, mask: %d\n", path, mask);
    return 0;
}

int cql_truncate(const char* path, off_t size) {
    debug("truncate: %s, size: %lld\n", path, size);
    return cassandraFS->truncate(path, size);
}

int cql_ftruncate(const char* path, off_t size, struct fuse_file_info* fi) {
    debug("ftruncate: %s, size: %lld\n", path, size);
    return cassandraFS->truncate(path, size);
}



int cql_getattr(const char *path, struct stat *stbuf) {
    debug("getattr: %s\n", path);
    struct cfs_attrs cfs;

    return cassandraFS->getattr(path, stbuf, &cfs);
}

int cql_fgetattr(const char* path, struct stat* stbuf, struct fuse_file_info *info) {
    debug("fgetattr: %s\n", path);
    struct cfs_attrs cfs;
    
    return cassandraFS->getattr(path, stbuf, &cfs);
}

long min(long a, long b) {
    if (a<b)
        return a;

    return b;
}

int cql_write(const char* path, const char *param_buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    debug("write: %s, size: %zu, offset: %lld\n", path, size, offset);
    const unsigned char* buf = (unsigned char*)param_buf;
    
    StatCache* stat_cache_item = stat_cache[path];
    char uuid_string[CASS_UUID_STRING_LENGTH];
    cass_uuid_string(stat_cache_item->physical_file_id, uuid_string);
    FileCache* cfs_cache_item = cfs_stat_cache[uuid_string];

    if (cfs_cache_item->cfs.block_size <= 0) {
        debug("write: invalid block size: %d", cfs_cache_item->cfs.block_size);
        return -EIO;
    }

    int current_block = offset / cfs_cache_item->cfs.block_size;
    int current_block_offset = offset % cfs_cache_item->cfs.block_size;
    long bytes_written = 0;

    while (bytes_written < size) {
        long bytes_to_write = min(size - bytes_written, cfs_cache_item->cfs.block_size - current_block_offset);

        cassandraFS->update_block(&cfs_cache_item->cfs.physical_file_id,
                                  current_block,
                                  current_block_offset,
                                  buf + bytes_written,
                                  bytes_to_write,
                                  &stat_cache_item->stat,
                                  &cfs_cache_item->cfs,
                                  &cfs_cache_item->spool);

        bytes_written += bytes_to_write;
        current_block++;
        current_block_offset = 0;
    }
    
    return bytes_written;
}

int cql_open(const char *path, struct fuse_file_info *fi) {
    debug("open: %s\n", path);
    establish_cache(path);

    return 0;
}

int cql_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    debug("readdir: %s\n", path);
    int direxists = 0;

    CassStatement* statement_entry = cass_statement_new("select mode FROM entries WHERE path = ?", 1);
    cass_statement_bind_string(statement_entry, 0, path);
    CassFuture* entry_result_future = cass_session_execute(cassandraCtxt->session, statement_entry);
    cass_statement_free(statement_entry);

    CassFuture* result_future = cassandraFS->sub_entries(path, 0);

    int res1 = cass_future_error_code(entry_result_future) == CASS_OK;
    int res2 = cass_future_error_code(result_future) == CASS_OK;

    if (res1 && res2) {
        /* Retrieve result set and iterate over the rows */
        const CassResult* result = cass_future_get_result(entry_result_future);
        CassIterator* rows = cass_iterator_from_result(result);

        if (cass_iterator_next(rows)) {
            filler(buf, ".", NULL, 0);           /* Current directory (.)  */
            filler(buf, "..", NULL, 0);          /* Parent directory (..)  */
            direxists = 1;
        }

        cass_iterator_free(rows);

        if (direxists) {
            /* Retrieve result set and iterate over the rows */
            const CassResult* result2 = cass_future_get_result(result_future);
            CassIterator* rows2 = cass_iterator_from_result(result2);

            while (cass_iterator_next(rows2)) {
                const CassRow* row = cass_iterator_get_row(rows2);
                const CassValue* value = cass_row_get_column(row, 0);

                const char* sub_path;
                size_t sub_path_length;
                cass_value_get_string(value, &sub_path, &sub_path_length);
                // Turn non null terminating string into null terminating string
                char *sub_path_null_terminating = (char*)calloc(1, sub_path_length + 1);
                memcpy(sub_path_null_terminating, sub_path, sub_path_length);
                filler(buf, sub_path_null_terminating, NULL, 0); 
                free(sub_path_null_terminating);
            }

            cass_result_free(result2);
            cass_iterator_free(rows2);
        }
    }

    if (!res1) {
        cassandra_log_error(entry_result_future);
    }

    if (!res2) {
        cassandra_log_error(result_future);
    }

    cass_future_free(entry_result_future);
    cass_future_free(result_future);
    return res1 && res2 ? (direxists ? 0 : -ENOENT) : -EACCES;
}

int cql_read(const char *path, char *param_buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    debug("read: %s, size: %zu, offset: %lld\n", path, size, offset);
    unsigned char* buf = (unsigned char*)param_buf;
    StatCache* stat_cache_item = stat_cache[path];
    char uuid_string[CASS_UUID_STRING_LENGTH];
    cass_uuid_string(stat_cache_item->physical_file_id, uuid_string);
    FileCache* cfs_cache_item = cfs_stat_cache[uuid_string];

    if (cfs_cache_item->cfs.block_size <= 0) {
        debug("write: invalid block size: %d", cfs_cache_item->cfs.block_size);
        return -EIO;
    }

    int current_block = offset / cfs_cache_item->cfs.block_size;
    int current_block_offset = offset % cfs_cache_item->cfs.block_size;
    long bytes_read = 0;

    while (bytes_read < size
           && offset + bytes_read < stat_cache_item->stat.st_size
           && current_block * cfs_cache_item->cfs.block_size < stat_cache_item->stat.st_size) {
        int length = 0;
        unsigned char* data = cassandraFS->read_block(&(cfs_cache_item->cfs.physical_file_id), current_block, &length);
        int bytes_to_be_copied = min(length-current_block_offset, size-bytes_read);

        memcpy(buf + bytes_read, data + current_block_offset, bytes_to_be_copied);
        free(data);

        bytes_read += bytes_to_be_copied;
        current_block++;
        current_block_offset = 0;
    }

    debug("bytes_read: %ld", bytes_read);
    return bytes_read;
}

void* cql_init(struct fuse_conn_info *conn) {
    openlog("cqlfs", 0, LOG_DAEMON);
    debug("Starting CQLFS");
    /* Add contact points */
    cassandraCtxt = new CassandraContext();

    CassFuture* connect_future = NULL;

    cass_cluster_set_contact_points(cassandraCtxt->cluster, "127.0.0.1");
    connect_future = cass_session_connect_keyspace(cassandraCtxt->session, cassandraCtxt->cluster, "cqlfs");

    if (cass_future_error_code(connect_future) != CASS_OK) {
        /* Handle error */
        cassandra_log_error(connect_future);
        exit(1);
    }
    
    cass_cluster_set_num_threads_io(cassandraCtxt->cluster, 20);
    
    cass_cluster_set_core_connections_per_host(cassandraCtxt->cluster, 4);
    
    cass_cluster_set_max_connections_per_host(cassandraCtxt->cluster, 20);
    
    cassandraFS = new CassandraFS(cassandraCtxt);

    debug("Connection to Cassandra successful");
    cassandra_log_keyspaces(cassandraCtxt);
    
    return NULL;
}

void cql_destroy() {
    closelog();
}

int cql_setxattr(const char* path, const char* name, const char* value, size_t size, int flags) {
    not_implemented("setxattr: %s", path);
}

int cql_getxattr(const char* path, const char* name, char* value, size_t size) {
    not_implemented("getxattr: %s", path);
}

int cql_listxattr(const char* path, const char* list, size_t size) {
    not_implemented("listxattr: %s", path);
}

int cql_removexattr(const char *path, const char *name) {
    not_implemented("removexattr: %s", path);
}

int cql_utimens(const char* path, const struct timespec ts[]) {
    debug("utimens: %s", path);

    return cassandraFS->update_timestamps(path, ts[0], ts[1]);
}

int cql_bmap(const char* path, size_t blocksize, uint64_t* blockno) {
    not_implemented("bmap: %s", path);
}

/*
int cql_poll(const char* path, struct fuse_file_info* fi, struct fuse_pollhandle* ph, unsigned* reventsp) {
    debug("poll: %s", path);
    return -ENOSYS;
}
*/

int cql_releasedir(const char* path, struct fuse_file_info *fi) {
    not_implemented("releasedir: %s", path);
}

// No need to flush since we don't cache anything
int cql_flush(const char* path, struct fuse_file_info* fi) {
    debug("flush: %s", path);

    return 0;
}

int create_file_entry(const char* path, mode_t mode) {
    int err = cassandraFS->create_file(path, mode);

    if (err != CASS_OK) {
        return -EIO;
    }

    return 0;
}

int cql_mkdir(const char* path, mode_t mode) {
    debug("mkdir: %s\n", path);

    int return_code = create_file_entry(path, mode);

    if (return_code == 0) {
        return 0;
    }

    return -EACCES;
}



int cql_create(const char* path, mode_t mode, struct fuse_file_info *fi) {
    debug("create: %s, mode: %x", path, mode);

    int return_code = create_file_entry(path, mode);

    if (return_code == 0) {
        establish_cache(path);
        return 0;
    }

    return -EACCES;
}

int cql_opendir(const char* path, struct fuse_file_info* fi) {
    not_implemented("opendir: %s", path);
}

int cql_release(const char* path, struct fuse_file_info *fi) {
    debug("release: %s", path);
    
    release_cache(path);

    return 0;
}

int cql_mknod(const char* path, mode_t mode, dev_t rdev) {
    not_implemented("mknod: %s", path);
}

int cql_lock(const char* path, struct fuse_file_info* fi, int cmd, struct flock* locks) {
    debug("lock: %s", path);

    return 0;
}

int cql_unlink(const char* path) {
    debug("unlink: %s", path);

    return cassandraFS->unlink(path);
}

#define PERMISSION_MASK 07777
int cql_chmod(const char* path, mode_t mode) {
    debug("chmod: %s", path);

    struct stat stat;
    struct cfs_attrs cfs_attrs;

    cassandraFS->getattr(path, &stat, &cfs_attrs);

    int permissions = stat.st_mode & 07777;
    int new_permissions = mode & 07777;
    
    if (permissions != new_permissions) {
        mode_t new_mode = (stat.st_mode & ~PERMISSION_MASK) | new_permissions;

        return cassandraFS->update_mode(path, new_mode);
    }

    return 0;
}

int cql_chown(const char* path, uid_t uid, gid_t gid) {
    not_implemented("chown: %s", path);
}

int hardlink(const char* from, const char* to) {
    return cassandraFS->hardlink(from, to);
}

int cql_rename(const char* from, const char* to) {
    debug("rename: %s -> %s", from, to);

    int err = hardlink(from, to);

    if (err != 0) {
        return err;
    }

    CassFuture* result_future = cassandraFS->remove_entry(from);
    CassFuture* result_future2 = cassandraFS->remove_sub_entry(from);

    if (cass_future_error_code(result_future) != CASS_OK) {
        /* Handle error */
        cassandra_log_error(result_future);
        err = -EIO;
    }

    if (cass_future_error_code(result_future2) != CASS_OK) {
        /* Handle error */
        cassandra_log_error(result_future2);
        err = -EIO;
    }

    cass_future_free(result_future);
    cass_future_free(result_future2);

    return err;
}

int cql_readlink(const char* path, char* buf, size_t size) {
    not_implemented("readlink: %s", path);
}

int cql_symlink(const char* to, const char* from) {
    not_implemented("symlink: %s -> %s", from, to);
}

int cql_link(const char* to, const char* from) {
    not_implemented("link: %s -> %s", from, to);
}

int cql_statfs(const char* path, struct statvfs* stbuf) {
    not_implemented("statfs: %s", path);
}

int dir_has_files(const char* path) {
    CassFuture* result_future = cassandraFS->sub_entries(path, 1);
    int rows = 0;

    if (cass_future_error_code(result_future) != CASS_OK) {
        cass_future_free(result_future);
        return 1;
    }

    const CassResult* result = cass_future_get_result(result_future);

    rows = cass_result_row_count(result);
    cass_result_free(result);
    cass_future_free(result_future);
    return (rows > 0);
}

int cql_rmdir(const char* path) {
    debug("rmdir: %s", path);

    if (dir_has_files(path)) {
        return -ENOTEMPTY;
    }

    return cassandraFS->unlink(path);
}

int cql_fsync(const char* path, int isdatasync, struct fuse_file_info* fi) {
    not_implemented("fsync: %s", path);
}

int cql_fsyncdir(const char* path, int isdatasync, struct fuse_file_info* fi) {
    not_implemented("fsyncdir: %s", path);
}

struct fuse_operations cqlfs_filesystem_operations = {
    .fgetattr    = cql_fgetattr, 
    .access      = cql_access,
    .getattr     = cql_getattr,
    .open        = cql_open,
    .read        = cql_read,
    .write       = cql_write,
    .truncate    = cql_truncate,
    .ftruncate   = cql_ftruncate,
    .readdir     = cql_readdir,
    .mkdir       = cql_mkdir,  
    .init        = cql_init,
//    .destroy     = cql_destroy,
    .readlink    = cql_readlink,
    .mknod       = cql_mknod,
    .symlink     = cql_symlink,
    .unlink      = cql_unlink,
    .rmdir       = cql_rmdir,
    .rename      = cql_rename,
    .link        = cql_link,
    .chmod       = cql_chmod,
    .chown       = cql_chown,
    .utimens     = cql_utimens,
    .create      = cql_create,
//    .statfs      = cql_statfs,
    .release     = cql_release,
//    .opendir     = cql_opendir,
//    .releasedir  = cql_releasedir,
    .fsync       = cql_fsync,
//    .flush       = cql_flush,
    .fsyncdir    = cql_fsyncdir,
//    .lock        = cql_lock,
    .bmap        = cql_bmap,
//    .poll        = cql_poll,
#ifdef HAVE_SETXATTR
    .setxattr = cql_setxattr,
    .getxattr = cql_getxattr,
    .listxattr = cql_listxattr,
    .removexattr = cql_removexattr,
#endif
};

#define ADDITIONAL_PARAMS 4
int main(int argc, char **argv) {
    char* param1 = (char*)"-o";
    char* param2 = (char*)"nolocalcaches";
    // char* param3 = (char*)"-s";
    char* param4 = (char*)"iosize=" DEFAULT_BLOCK_SIZE;
    
    int new_argc = argc+ADDITIONAL_PARAMS;
    char** new_argv = (char**)malloc(sizeof(char*) * (new_argc));
    new_argv[0] = argv[0];
    new_argv[1] = param1;
    new_argv[2] = param2;
    new_argv[3] = param1;
    new_argv[4] = param4;
    //new_argv[5] = param3;

    for (int i=1;i<argc;i++) {
        new_argv[i+ADDITIONAL_PARAMS] = argv[i];
    }
    
    return fuse_main(argc, argv, &cqlfs_filesystem_operations, NULL);
}
