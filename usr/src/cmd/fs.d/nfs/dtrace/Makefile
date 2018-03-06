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
# Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
#

SRCS=nfs-trace.d nfs-time.d

include $(SRC)/cmd/Makefile.cmd

ROOTNFSDTRACEDIR = $(ROOTLIB)/nfs/dtrace
ROOTNFSDTRACEFILE = $(SRCS:%=$(ROOTNFSDTRACEDIR)/%)

$(ROOTNFSDTRACEFILE):= FILEMODE = 0555

$(ROOTNFSDTRACEDIR):
	$(INS.dir)

$(ROOTNFSDTRACEDIR)/%: %
	$(INS.file)

all:

clean:

include $(SRC)/cmd/Makefile.targ

install: all $(ROOTNFSDTRACEDIR) .WAIT $(ROOTNFSDTRACEFILE)
