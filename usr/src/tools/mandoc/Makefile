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
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
#


PROG=		mandoc

CMDDIR=	$(SRC)/cmd/mandoc

include ../Makefile.tools

include $(SRC)/cmd/mandoc/Makefile.common

SRCS=	$(mandoc_OBJS:%.o=$(CMDDIR)/%.c)
CLEANFILES=	$(PROG) $(OBJS)
OBJS= $(mandoc_OBJS)
PROG= mandoc

.KEEP_STATE:

install: all .WAIT $(ROOTONBLDMACHPROG)

$(PROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

all:		$(PROG)


%.o:		$(CMDDIR)/%.c
		$(COMPILE.c) -o $@ $<

%.o:		$(LIBDIR)/%.c
		$(COMPILE.c) -o $@ $<

clean:
		$(RM) $(CLEANFILES)

include ../Makefile.targ

