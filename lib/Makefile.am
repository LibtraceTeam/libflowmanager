lib_LTLIBRARIES = libflowmanager.la
include_HEADERS = libflowmanager.h tcp_reorder.h

plugin_SOURCES= plugins/standard.cc plugins/fixed.cc plugins/lfmplugin.cc \
	plugins/lfmplugin.h

libflowmanager_la_SOURCES = libflowmanager.cc flowid.cc tcp_reorder.c \
	$(plugin_SOURCES)

INCLUDES = @ADD_INCLS@
libflowmanager_la_CPPFLAGS = -I plugins/
libflowmanager_la_LIBADD = @ADD_LIBS@ @LTLIBOBJS@
libflowmanager_la_LDFLAGS = -version-info 3:0:0 @ADD_LDFLAGS@
