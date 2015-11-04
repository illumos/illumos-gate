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
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
#

CMDDIR=		$(SRC)/cmd/mandoc

include		../Makefile.tools
include		$(CMDDIR)/Makefile.common

.KEEP_STATE:

all:		$(PROG)

install:	all .WAIT $(ROOTONBLDMACHPROG)

clean:
		$(RM) $(PROG) $(OBJS)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

%.o:		$(CMDDIR)/%.c
		$(COMPILE.c) -o $@ $<

include		../Makefile.targ
