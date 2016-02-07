#include "cqlfs_common.h"

void _cassandra_log_error(const char* file, int line, CassFuture *error_future) {
    const char* message;
    size_t message_length;
    cass_future_error_message(error_future, &message, &message_length);
    debug("Error with operation (%s:%d): '%.*s'\n", file, line, (int)message_length, message);
}

void cassandra_log_keyspaces(CassandraContext* ctxt) {
    CassStatement* statement = cass_statement_new("SELECT keyspace_name FROM system.schema_keyspaces", 0);
    CassFuture* result_future = cass_session_execute(ctxt->session, statement);

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
