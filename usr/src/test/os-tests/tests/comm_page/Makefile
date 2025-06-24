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
# Copyright 2025 Oxide Computer Company
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

SCRIPTS = comm_page_pre comm_page_ktest

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/comm_page

CMDS = $(PROG:%=$(TESTDIR)/%) \
	$(SCRIPTS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all:

install: $(CMDS)

clobber: clean

clean:

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %.ksh
	$(INS.rename)
