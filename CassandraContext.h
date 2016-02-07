#ifndef CASSANDRACONTEXT_H
#define CASSANDRACONTEXT_H

#include <cassandra.h>

class CassandraContext {
public:
    CassCluster* cluster;
    CassSession* session;
    CassTimestampGen* timestamp_gen;
    CassUuidGen* uuid_gen;

    CassandraContext();
    virtual ~CassandraContext();
private:

};

#endif /* CASSANDRACONTEXT_H */

