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
# Copyright 2015 Joyent, Inc.
#

PROG =		cgrpmgr

PROG_OBJS =	cgrpmgr.o

OBJS =		$(PROG_OBJS)
SRCS =		$(PROG_OBJS:%.o=%.c)

all:		$(PROG)

include ../Makefile.lx
include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

# override the install directory
ROOTBIN =	$(ROOTBRANDDIR)
CLOBBERFILES =	$(OBJS) $(ROOTPROG)

UTSBASE =	$(SRC)/uts

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I$(UTSBASE)/common/brand/lx/cgroups
LDLIBS +=

.KEEP_STATE:

install: all $(ROOTPROG)

clean:
	$(RM) $(PROG) $(OBJS)

lint: lint_PROG lint_SRCS

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

include $(SRC)/cmd/Makefile.targ
