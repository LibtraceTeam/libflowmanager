lib_LTLIBRARIES = libflowmanager.la
include_HEADERS = libflowmanager.h tcp_reorder.h

libflowmanager_la_SOURCES = libflowmanager.cc flowid.cc tcp_reorder.c

INCLUDES = @ADD_INCLS@
libflowmanager_la_LIBADD = @ADD_LIBS@ @LTLIBOBJS@
libflowmanager_la_LDFLAGS = -version-info 2:4:0 @ADD_LDFLAGS@
