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
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

PROG=	bind-helper
SRCS=	bind-helper.c

include ../../Makefile.cmd
include ../Makefile.smbsrv.defs

LDLIBS += -lsocket -lnsl

ROOTLIBSMBSRVDIR = $(ROOTLIB)/smbsrv
ROOTLIBSMBSRVPROG = $(PROG:%=$(ROOTLIBSMBSRVDIR)/%)

.KEEP_STATE:

all:		$(PROG)

clean:
	$(RM) $(OBJS)

lint:		lint_SRCS

$(PROG):	$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

include ../../Makefile.targ

$(ROOTLIBSMBSRVDIR)/%: %
	$(INS.file)

install: all .WAIT $(ROOTLIBSMBSRVPROG)
