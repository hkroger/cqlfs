# cqlfs
Experimental Fuse FS which uses Cassandra as the store. Works with OSX Fuse installed with homebrew. PR to support more operating systems and setups are gladly accepted.

## Build

    $ cmake .
    $ make
    
## Initialize Cassandra store

Currently it's hardcoded to use keyspace `cqlfs` and connect to `127.0.0.1`.

    $ cqlsh < schema.cql
    $ cqlsh < bootstrap.cql 

## Mount device 

    $ ./cqlfs /mnt/blah
    
    
## TODO

These are in no particular order.

* Figure out reasonable caching scheme (invalidate caches using some queue? Kafka?)
* Test multi-threading properly
* Add tests
* Add performance tests
* Test mounting from several places and see how that works.
* Configuration options for keyspace name, hosts, etc.
* Support stats
* File handle support
* Error handling
* CQL consistency handling
* Delete blocks when truncating
* Speedup writes
	* Support write caching
	* Make writes even more asynchronous
* Access control


## FAQ

Q: Why does this exist?<br />
A: Mainly to experiment with Fuse and to create a naive implementation of FS that uses Cassandra. It has been a topic for long in the cassandra user mailing list and this is there to just test how it can be done.

Q: What is it good for?<br />
A: That is still to be seen.

Q: Why C++?<br />
A: It seemed like a good idea because of native linking and stuff. In retrospect, this wasn't a smartest move because certain things are a bit more painful in C++ than in Java/Scala for example.

Q: Is it fast?<br />
A: Actually it's the slowest FS I have seen in my life. See TODO.

Q: Can I put it in production?<br />
A: Well, you can. If you are crazy.