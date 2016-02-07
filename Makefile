CC=gcc 
CPPFLAGS=
CFLAGS=-Wall -Werror -g
INCLUDES=-I/usr/local/include/osxfuse/fuse 
OBJS=$(patsubst %.c,%.o,$(wildcard *.c))
LDLIBS=-lcassandra -losxfuse
DEPS=*.h

cqlfs: $(OBJS)
	$(CC) $(OBJS) $(LDLIBS)  -o cqlfs 

%.o: %.c $(DEPS)
	$(CC) $(INCLUDES) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY : clean
clean :
	rm $(OBJS)
	rm cqlfs