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
# Copyright 2020 Oxide Computer Company
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ROOTOPTPKG = $(ROOT)/opt/util-tests/tests/head
PROG = head_test
DATAFILES =			\
	5221.in			\
	5221.out		\
	multi.1.out		\
	multi.4.out		\
	rings.1.out		\
	rings.2.out		\
	rings.3.out		\
	rings.5.out		\
	rings.in		\
	stdin-nul.1.out		\
	stdin-nul.2.out		\
	stdin-nul.3.out		\
	stdin.1.out		\
	stdin.11.out		\
	stdin.2.out		\
	stdin.3.out		\
	stdin.5.out		\
	stdin.multi.out		\
	stdin.nonewline.out


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
