CC = g++
CFLAGS = -ggdb -Wall

ACLPARSE_OBJS = util.o readfile.o acl.o prefix.o link.o interface.o policy.o binpack.o cube.o aclparse.o
BIN_OBJS = binpack.o bintest.o

.PHONY: all clean 

all: clean aclparse

.cc.o:
	$(CC) $(CFLAGS) -c $<

.c.o:
	$(CC) $(CFLAGS) -c $<

aclparse: $(ACLPARSE_OBJS)
	$(CC) $(CFLAGS) -o aclparse $(ACLPARSE_OBJS) -lnsl -pg -lpthread
 
bin: $(BIN_OBJS)
	$(CC) $(CFLAGS) -o bin $(BIN_OBJS) -lnsl -pg -lpthread

clean:
	rm -f *.o *~ aclparse bin
