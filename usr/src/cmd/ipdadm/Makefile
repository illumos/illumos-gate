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
# Copyright (c) 2017 Joyent, Inc.  All rights reserved.
#

PROG= ipdadm
OBJS = ipdadm.o
SRCS = $(OBJS:%.o=../%.c)


include ../Makefile.cmd
include ../Makefile.ctf

CLEANFILES += $(OBJS)
CFLAGS += $(CCVERBOSE)
LDLIBS += -lipd

.KEEP_STATE:

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	-$(RM) $(CLEANFILES)

lint: lint_PROG

%.o: ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

include ../Makefile.targ
