#include "CassandraContext.h"

CassandraContext::CassandraContext() {
    cluster = cass_cluster_new();
    session = cass_session_new();
    timestamp_gen = cass_timestamp_gen_monotonic_new();
    uuid_gen = cass_uuid_gen_new();
    cass_cluster_set_timestamp_gen(cluster, timestamp_gen);
}

CassandraContext::~CassandraContext() {
}

