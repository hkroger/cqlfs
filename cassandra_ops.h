#ifndef CASSANDRA_OPS_H
#define CASSANDRA_OPS_H

#include <cassandra.h>

void cassandra_log_error(CassFuture *error_future);

int cassandra_copy_full_entry(CassSession* session, const char* from, const char* to);
CassFuture* cassandra_create_entry(CassSession* session, const char* path, mode_t mode);
CassFuture* cassandra_create_sub_entry(CassSession* session, const char* path, mode_t mode);
CassFuture* cassandra_remove_entry(CassSession* session, const char* path);
CassFuture* cassandra_remove_sub_entry(CassSession* session, const char* path);
CassFuture* cassandra_remove_sub_entries(CassSession* session, const char* path);
void cassandra_log_keyspaces(CassSession* session);

#endif /* CASSANDRA_OPS_H */

