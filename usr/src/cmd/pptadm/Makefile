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
# Copyright 2018 Joyent, Inc.
#

PROG = pptadm
OBJS = pptadm.o
SRCS = $(OBJS:%.o=%.c)

include ../Makefile.cmd
include ../Makefile.ctf

LDLIBS += -lofmt -lppt -lnvpair

CSTD = $(CSTD_GNU99)
C99LMODE = -Xc99=%all

CLEANFILES += $(OBJS)

.KEEP_STATE:

all: $(OBJS) $(PROG)

install: all $(ROOTUSRSBINPROG)

clean:
	-$(RM) $(CLEANFILES)

lint: lint_SRCS

%.o: ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

include ../Makefile.targ
