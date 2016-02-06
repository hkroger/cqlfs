#ifndef CQLFS_COMMON_H
#define CQLFS_COMMON_H

#include <syslog.h>

#define debug(x...) syslog(LOG_NOTICE,x)

#endif /* CQLFS_COMMON_H */

