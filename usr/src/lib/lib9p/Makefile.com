#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

LIBRARY=	lib9p.a
VERS=		.1

OBJECTS=	backend/fs.o \
		connection.o \
		genacl.o \
		hashtable.o \
		log.o \
		pack.o \
		request.o \
		rfuncs.o \
		sbuf/sbuf.o \
		threadpool.o \
		transport/socket.o \
		utils.o
HDRS =		lib9p.h

LOBJDIRS=	backend transport sbuf

include ../../Makefile.lib

LIBS =		$(DYNLIB)
LDLIBS +=	-lc -lcustr -lsocket -lsec -lnvpair

SRCDIR =	..

CSTD =		$(CSTD_GNU99)

CFLAGS +=	$(CCVERBOSE)

CPPFLAGS +=	-D__illumos__
CPPFLAGS +=	-D_POSIX_PTHREAD_SEMANTICS -D__EXTENSIONS__
CPPFLAGS +=	-I../common -I../common/backend
$(NOT_RELEASE_BUILD)CPPFLAGS +=	-DL9P_DEBUG=L9P_DEBUG

SMOFF += all_func_returns

.KEEP_STATE:

all: $(LIBS)

$(LIBS): mkpicdirs

mkpicdirs:
	@mkdir -p $(LOBJDIRS:%=pics/%)

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/backend/%.o: ../common/backend/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/transport/%.o: ../common/transport/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(ROOTHDRDIR)/%.h: ../common/%.h
	$(INS.file)

include ../../Makefile.targ
