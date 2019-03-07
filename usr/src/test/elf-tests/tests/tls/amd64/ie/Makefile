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

# Copyright 2018, Richard Lowe.

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG =	amd64-ie-test

DATAFILES =			\
	Makefile.test		\
	style1-func-with-r12.s	\
	style1-func-with-r13.s	\
	style1-func.s		\
	style1-main.s		\
	style2-with-badness.s	\
	style2-with-r12.s	\
	style2-with-r13.s	\
	style2.s

ROOTOPTPKG = $(ROOT)/opt/elf-tests
TESTDIR = $(ROOTOPTPKG)/tests/tls/amd64/ie

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555


DATA = $(DATAFILES:%=$(TESTDIR)/%)
$(DATA) := FILEMODE = 0444

all: $(PROG)

install: all $(CMDS) $(DATA)

lint:

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(CLEANFILES)

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
