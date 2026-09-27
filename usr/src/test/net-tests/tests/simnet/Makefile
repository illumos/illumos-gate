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
# Copyright 2026 Michal Skalski
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd

ROOTOPTPKG = $(ROOT)/opt/net-tests
TESTDIR = $(ROOTOPTPKG)/tests/simnet

PROG = mtu
CMDS = $(PROG:%=$(TESTDIR)/%)
FILEMODE = 0555

include $(SRC)/test/Makefile.com

install: $(CMDS)

clobber: clean
	$(RM) $(CMDS)

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %.ksh
	$(INS.rename)
