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
# Copyright 2016 Joyent, Inc.
#

PROG= xhci_portsc

ROOTLIBXHCI = $(ROOTLIB)/xhci
ROOTLIBXHCIPROG = $(PROG:%=$(ROOTLIBXHCI)/%)

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE)
CPPFLAGS += -I$(SRC)/uts/common/
LDLIBS += -ldevinfo

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTLIBXHCIPROG)

clean:

lint:	lint_PROG

$(ROOTLIBXHCI):
	$(INS.dir)

$(ROOTLIBXHCI)/%: % $(ROOTLIBXHCI)
	$(INS.file)

include ../Makefile.targ
