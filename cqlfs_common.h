#ifndef CQLFS_COMMON_H
#define CQLFS_COMMON_H

#include <syslog.h>
#include "CassandraContext.h"


#define debug(x...) syslog(LOG_NOTICE,x)

#define cassandra_log_error(x) _cassandra_log_error(__FILE__, __LINE__, x)

void _cassandra_log_error(const char* file, int line, CassFuture *error_future);
void cassandra_log_keyspaces(CassandraContext* ctxt);

#endif /* CQLFS_COMMON_H */

