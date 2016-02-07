#ifndef CASSANDRA_OPS_H
#define CASSANDRA_OPS_H

#include <stdio.h>
#include <sys/stat.h>
#include "CassandraContext.h"

struct cfs_attrs {
    int block_size; // block size in cassandra
    CassUuid physical_file_id;
};

class CassandraFS {

private:
    CassandraContext* ctxt;

public:
    CassandraFS(CassandraContext* ctxt);

    int hardlink(const char* from, const char* to);
    int truncate(const char* path,off_t size);
    int unlink(const char* path);
    CassError create_file(const char* path, mode_t mode);
    CassFuture* sub_entries(const char* path, int limit);
    int update_block(
        CassUuid* physical_file_id,
        int block,
        int block_offset,
        const unsigned char* buf,
        int bytes_to_write,
        struct stat* stat,
        struct cfs_attrs* cfs_attrs);

    void update_file_length(CassUuid* physical_file_id, long size);
    int getattr(const char* path, struct stat *stbuf, struct cfs_attrs *cfs_attrs);
    unsigned char* read_block(CassUuid* physical_file_id, int block, int* bytes_read);
    void write_block(CassUuid* physical_file_id, int block, const unsigned char* data, int length);
    int update_mode(const char* path, mode_t new_mode);
    
    CassFuture* remove_entry(const char* path);
    CassFuture* remove_sub_entry(const char* path);

protected:
    CassFuture* create_entry(const char* path, CassUuid* uuid, mode_t mode);
    CassFuture* create_physical_file(CassUuid* uuid);
    CassFuture* create_sub_entry(const char* path);
    CassFuture* remove_sub_entries(const char* path);
    CassFuture* remove_physical_file(struct stat* stat, struct cfs_attrs* cfs_attrs);
    CassError read_physical_file_info(struct stat* stat, struct cfs_attrs* cfs_attrs);
};



#endif /* CASSANDRA_OPS_H */

