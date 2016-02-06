#include <errno.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <time.h>

#include "cqlfs_common.h"
#include "cassandra_ops.h"

void cassandra_log_error(CassFuture *error_future) {
    const char* message;
    size_t message_length;
    cass_future_error_message(error_future, &message, &message_length);
    debug("Error with operation: '%.*s'\n", (int)message_length, message);
}

CassFuture* cassandra_create_entry(CassSession* session, const char* path, mode_t mode) {
    CassStatement* statement = cass_statement_new("INSERT INTO entries(path, mode, created_at, modified_at) VALUES(?,?,?,?)", 4);

    cass_statement_bind_string(statement, 0, path);
    cass_statement_bind_int32(statement, 1, mode);
    cass_statement_bind_int64(statement, 2, time(NULL)*1000);
    cass_statement_bind_int64(statement, 3, time(NULL)*1000);

    CassFuture* result_future = cass_session_execute(session, statement);

    cass_statement_free(statement);

    return result_future;
}

CassFuture* cassandra_create_sub_entry(CassSession* session, const char* path, mode_t mode) {
    CassStatement* statement = cass_statement_new("INSERT INTO sub_entries(sub_path, mode, created_at, parent_path) VALUES(?,?,?,?)", 4);

    char *subpathc = strdup(path);
    char *parentpathc = strdup(path);

    cass_statement_bind_string(statement, 0, basename(subpathc));
    cass_statement_bind_int32(statement, 1, mode);
    cass_statement_bind_int64(statement, 2, time(NULL)*1000);
    cass_statement_bind_string(statement, 3, dirname(parentpathc));

    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);
    free(subpathc);
    free(parentpathc);

    return result_future;
}

void cassandra_log_keyspaces(CassSession* session) {
    CassStatement* statement = cass_statement_new("SELECT keyspace_name FROM system.schema_keyspaces", 0);
    CassFuture* result_future = cass_session_execute(session, statement);

    if(cass_future_error_code(result_future) == CASS_OK) {
        const CassResult* result = cass_future_get_result(result_future);
        CassIterator* rows = cass_iterator_from_result(result);

        while(cass_iterator_next(rows)) {
            const CassRow* row = cass_iterator_get_row(rows);
            const CassValue* value = cass_row_get_column_by_name(row, "keyspace_name");

            const char* keyspace;
            size_t keyspace_length;
            cass_value_get_string(value, &keyspace, &keyspace_length);
            debug("keyspace_name: '%.*s'\n", (int)keyspace_length, keyspace);
        }

        cass_result_free(result);
        cass_iterator_free(rows);
    }
}

CassFuture* cassandra_remove_entry(CassSession* session, const char* path) {
    CassStatement* statement = cass_statement_new("DELETE FROM entries WHERE path = ?", 1);
    cass_statement_bind_string(statement, 0, path);
    CassFuture* result_future = cass_session_execute(session, statement);

    cass_statement_free(statement);
    return result_future;
}

CassFuture* cassandra_remove_sub_entry(CassSession* session, const char* path) {
    CassStatement* statement = cass_statement_new("DELETE FROM sub_entries WHERE parent_path = ? AND sub_path = ?", 2);
    char *subpathc = strdup(path);
    char *parentpathc = strdup(path);

    cass_statement_bind_string(statement, 0, dirname(parentpathc));
    cass_statement_bind_string(statement, 1, basename(subpathc));

    free(subpathc);
    free(parentpathc);

    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);

    return result_future;
}

CassFuture* cassandra_remove_sub_entries(CassSession* session, const char* path) {
    CassStatement* statement = cass_statement_new("DELETE FROM sub_entries WHERE parent_path = ?", 1);
    cass_statement_bind_string(statement, 0, path);
    CassFuture* result_future = cass_session_execute(session, statement);

    cass_statement_free(statement);

    return result_future;
}

int cassandra_copy_full_entry(CassSession* session, const char* from, const char* to) {


    return -ENOSYS;
}
