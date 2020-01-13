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
# Copyright 2019 Robert Mustacchi
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ROOTOPTPKG = $(ROOT)/opt/util-tests/tests/sleep
PROG = sleeptest
DATAFILES = sleep.d sleep.awk

ROOTPROG = $(PROG:%=$(ROOTOPTPKG)/%)
ROOTDATA = $(DATAFILES:%=$(ROOTOPTPKG)/%)

$(ROOTDATA) := FILEMODE = 0444

all:

install: $(ROOTPROG) $(ROOTDATA)

lint:

clobber: clean

clean:

$(CMDS): $(TESTDIR)

$(ROOTOPTPKG):
	$(INS.dir)

$(ROOTOPTPKG)/%: %.ksh $(ROOTOPTPKG)
	$(INS.rename)

$(ROOTOPTPKG)/%: % $(ROOTOPTPKG)
	$(INS.file)
