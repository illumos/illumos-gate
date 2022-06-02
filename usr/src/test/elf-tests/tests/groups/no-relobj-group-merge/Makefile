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

# Copyright 2022, Richard Lowe.

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG =	no-relobj-group-merge

DATAFILES =	sections.s README.md

ROOTOPTPKG = $(ROOT)/opt/elf-tests
TESTDIR = $(ROOTOPTPKG)/tests/groups/no-relobj-group-merge

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

DATA = $(DATAFILES:%=$(TESTDIR)/%)
$(DATA) := FILEMODE = 0444

all:

install: all $(CMDS) $(DATA)

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(CLEANFILES)

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %.sh
	$(INS.rename)

$(TESTDIR)/%: %
	$(INS.file)
