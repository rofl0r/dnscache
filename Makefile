OBJS = dnscache.o hsearch.o udpserver.o

-include config.mak

all: dnscache

clean:
	rm -f $(OBJS) dnscache

dnscache: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

.PHONY: all clean
