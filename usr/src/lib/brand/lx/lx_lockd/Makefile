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
# Copyright 2017 Joyent, Inc.
#

PROG =	lx_lockd

PROG_OBJS = lockd.o nfs_tbind.o
UTIL_OBJS = thrpool.o

OBJS =	$(PROG_OBJS) $(UTIL_OBJS)
SRCS =	$(PROG_OBJS:%.o=%.c)

all:		$(PROG)

include ../Makefile.lx
include $(SRC)/cmd/Makefile.cmd

# override the install directory
ROOTBIN =	$(ROOTBRANDDIR)
CLOBBERFILES =	$(OBJS) $(ROOTPROG)

CPPFLAGS +=	-I$(SRC)/cmd/fs.d/nfs/lib
C99MODE =	$(C99_ENABLE)
LDLIBS +=	-lnsl -lsocket

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-function

.KEEP_STATE:

install: all $(ROOTPROG)

clean:
	$(RM) $(PROG) $(OBJS)

lint:
	$(LINT.c) -erroff=E_SEC_PRINTF_VAR_FMT lockd.c $(LDLIBS)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/cmd/fs.d/nfs/lib/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

include $(SRC)/cmd/Makefile.targ
