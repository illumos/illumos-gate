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
# Copyright 2015 Nexenta Systems, Inc.
#


PROG= nvmeadm

OBJS= nvmeadm.o nvmeadm_dev.o nvmeadm_print.o
SRCS= $(OBJS:%.o=%.c)

include ../Makefile.cmd

.KEEP_STATE:

CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-ldevinfo
CSTD=	$(CSTD_GNU99)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS) $(PROG)

lint:	lint_SRCS

include ../Makefile.targ
