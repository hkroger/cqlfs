CC=g++
CPPFLAGS=
CFLAGS=-Wall -Werror -g
INCLUDES=
OBJS=$(patsubst %.cpp,%.o,$(wildcard *.cpp))
LDLIBS=-lcassandra -losxfuse
DEPS=*.h

cqlfs: $(OBJS)
	$(CC) $(OBJS) $(LDLIBS)  -o cqlfs 

%.o: %.cpp $(DEPS)
	$(CC) $(INCLUDES) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY : clean
clean :
	rm $(OBJS)
	rm cqlfs