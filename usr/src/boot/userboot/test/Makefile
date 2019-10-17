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
# Copyright 2019 Toomas Soome <tsoome@me.com>
#

PROG=	test
OBJS=	test.o

include ../../../cmd/Makefile.cmd
include ../../../cmd/Makefile.cmd.64

all: $(PROG)

KEEP_STATE:

CPPFLAGS +=	-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
CPPFLAGS +=	-I.. -I../../sys
LDLIBS += -lumem

install: all $(ROOTPROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

include ../../../cmd/Makefile.targ
