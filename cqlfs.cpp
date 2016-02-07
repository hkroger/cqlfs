#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION  26
#include <osxfuse/fuse/fuse.h>

#include "cqlfs_common.h"

#include "CassandraFS.h"

#define not_implemented(x...) debug("not implemented: " x);return -ENOSYS;


CassandraContext* cassandraCtxt;
CassandraFS* cassandraFS;

int cql_access(const char* path, int mask) {
    debug("access: %s, mask: %d\n", path, mask);
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
    struct cfs_attrs cfs;
    struct stat stat;
    const unsigned char* buf = (unsigned char*)param_buf;
    cassandraFS->getattr(path, &stat, &cfs);

    if (cfs.block_size <= 0) {
        debug("write: invalid block size: %d", cfs.block_size);
        return -EIO;
    }

    int current_block = offset / cfs.block_size;
    int current_block_offset = offset % cfs.block_size;
    long bytes_written = 0;

    while (bytes_written < size) {
        long bytes_to_write = min(size - bytes_written, cfs.block_size - current_block_offset);

        int err = cassandraFS->update_block(&(cfs.physical_file_id), current_block, current_block_offset, buf + bytes_written, bytes_to_write, &stat, &cfs);

        if (err != 0) {
            return bytes_written;
        }

        bytes_written += bytes_to_write;
        current_block++;
        current_block_offset = 0;
    }

    return bytes_written;
}

int cql_open(const char *path, struct fuse_file_info *fi) {
    debug("open: %s\n", path);

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
    struct cfs_attrs cfs;
    struct stat stat;
    unsigned char* buf = (unsigned char*)param_buf;
    int err = cassandraFS->getattr(path, &stat, &cfs);

    if (err != 0) {
        return err;
    }

    if (cfs.block_size <= 0) {
        debug("write: invalid block size: %d", cfs.block_size);
        return -EIO;
    }

    int current_block = offset / cfs.block_size;
    int current_block_offset = offset % cfs.block_size;
    long bytes_read = 0;

    while (bytes_read < size && offset + bytes_read < stat.st_size) {
        int length = 0;
        unsigned char* data = cassandraFS->read_block(&(cfs.physical_file_id), current_block, &length);
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

    // TODO: actually update stuff
    return 0;
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
        return 0;
    }

    return -EACCES;
}

int cql_opendir(const char* path, struct fuse_file_info* fi) {
    not_implemented("opendir: %s", path);
}

int cql_release(const char* path, struct fuse_file_info *fi) {
    debug("release: %s", path);

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

int cql_chmod(const char* path, mode_t mode) {
    not_implemented("chmod: %s", path);
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


int main(int argc, char **argv) {
    return fuse_main(argc, argv, &cqlfs_filesystem_operations, NULL);
}
