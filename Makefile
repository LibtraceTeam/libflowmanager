PREFIX=/home/spa1/wdcap3
CPPFLAGS=-g -Wall -W -D_FILE_OFFSET_BITS=64 -I$(PREFIX)/include -I.
LDFLAGS=-L$(PREFIX)/lib
LDLIBS=-ltrace -lpacketdump

SOURCES=tcp_reorder.c libflowmanager.cc flowid.cc
HEADERS=tcp_reorder.h libflowmanager.h

all: libflowmanager

libflowmanager: $(SOURCES) $(HEADERS)
	g++ $(CPPFLAGS) -fpic -shared $(LDFLAGS) $(LDLIBS) $(SOURCES) -o libflowmanager.so

install:
	cp *.so $(PREFIX)/lib
	cp *.h $(PREFIX)/include

clean:
	rm -f *.o *.so

.PHONY: clean all

