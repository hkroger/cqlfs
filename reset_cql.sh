#!/bin/bash

cd `dirname $0`
echo "DROP KEYSPACE cqlfs;" | cqlsh
cqlsh < schema.cql
cqlsh < bootstrap.cql
