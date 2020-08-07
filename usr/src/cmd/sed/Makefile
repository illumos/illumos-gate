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
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
#


PROG=		sed
XPG4PROG=	sed
OBJS=		main.o compile.o misc.o process.o
SRCS=		$(OBJS:%.o=%.c)
POFILES=	$(OBJS:%.o=%.po)

include ../Makefile.cmd

CPPFLAGS +=	-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

CFLAGS += $(CCVERBOSE)

.KEEP_STATE:


all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE):	$(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(ROOTXPG4PROG):
	$(RM) $@
	$(LN) -s ../../bin/$(PROG) $@

install: all $(DIRS) $(ROOTPROG) $(ROOTXPG4PROG)

clean:
	$(RM) $(OBJS) $(POFILES)

include ../Makefile.targ
