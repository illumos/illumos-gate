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
# Copyright 2021 Oxide Computer Company
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ROOTOPTPKG = $(ROOT)/opt/util-tests/tests
ROOTOPTPKGAR = $(ROOT)/opt/util-tests/tests/ar
PROG = artest
OBJS = ar_test0.o ar_test1.o

ROOTPROG = $(PROG:%=$(ROOTOPTPKGAR)/%)
ROOTOBJS = $(OBJS:%=$(ROOTOPTPKGAR)/%)

$(ROOTOBJS) := FILEMODE = 0444

all: $(OBJS)

install: $(ROOTPROG) $(ROOTOBJS)

clobber: clean

clean:
	$(RM) $(OBJS)

$(ROOTOPTPKG):
	$(INS.dir)

$(ROOTOPTPKGAR): $(ROOTOPTPKG)
	$(INS.dir)

$(ROOTOPTPKGAR)/%: %.ksh $(ROOTOPTPKGAR)
	$(INS.rename)

$(ROOTOPTPKGAR)/%.o: %.o
	$(INS.file)
