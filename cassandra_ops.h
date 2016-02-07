#ifndef CASSANDRA_OPS_H
#define CASSANDRA_OPS_H

#include <cassandra.h>
#include <stdio.h>
#include <sys/stat.h>

struct cfs_attrs {
    int block_size; // block size in cassandra
};

void cassandra_log_error(CassFuture *error_future);

int cassandra_copy_full_entry(CassSession* session, const char* from, const char* to);
int cassandra_truncate(CassSession* session, const char* path,off_t size);
CassFuture* cassandra_create_entry(CassSession* session, const char* path, mode_t mode);
CassFuture* cassandra_create_sub_entry(CassSession* session, const char* path);
CassFuture* cassandra_remove_entry(CassSession* session, const char* path);
CassFuture* cassandra_remove_sub_entry(CassSession* session, const char* path);
CassFuture* cassandra_remove_sub_entries(CassSession* session, const char* path);
CassFuture* cassandra_sub_entries(CassSession* session, const char* path, int limit);
void cassandra_log_keyspaces(CassSession* session);
int cassandra_update_block(CassSession* session,
    const char* path,
    int block,
    int block_offset,
    const unsigned char* buf,
    int bytes_to_write,
    struct stat* stat,
    struct cfs_attrs* cfs_attrs);

int cassandra_getattr(CassSession* session, const char* path, struct stat *stbuf, struct cfs_attrs *cfs_attrs);
unsigned char* cassandra_read_block(CassSession* session, const char* path, int block, int* bytes_read);

#endif /* CASSANDRA_OPS_H */

