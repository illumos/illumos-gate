#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libsasl/Makefile.com
#

LIBRARY= libsasl.a
VERS= .1

SASLOBJS=	auxprop.o	canonusr.o	checkpw.o	client.o \
		common.o	config.o	dlopen.o	external.o \
		md5.o		saslutil.o	seterror.o	server.o

COMMONOBJS=	plugin_common.o

OBJECTS=	$(SASLOBJS) $(COMMONOBJS)

include ../../Makefile.lib

LIBS=		$(DYNLIB) $(LINTLIB)
SRCS=		$(SASLOBJS:%.o=../lib/%.c) $(COMMONOBJS:%.o=$(PLUGDIR)/%.c)
$(LINTLIB):= 	SRCS = $(SRCDIR)/$(LINTSRC)
LDLIBS +=	-lsocket -lc -lmd
LINTFLAGS +=	-DPIC
LINTFLAGS64 +=	-DPIC

SRCDIR=		../lib
PLUGDIR=	../plugin
MAPDIR= 	../spec/$(TRANSMACH)
SPECMAPFILE=	$(MAPDIR)/mapfile

CFLAGS +=	$(CCVERBOSE) $(XSTRCONST)
CFLAGS64 +=	$(XSTRCONST)
CPPFLAGS +=	-I../include -I$(PLUGDIR)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: $(PLUGDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
