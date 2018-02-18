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

# Copyright 2016, Richard Lowe.

include $(SRC)/Makefile.master
include $(SRC)/Makefile.master.64
include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64

ROOTOPTPKG = $(ROOT)/opt/libc-tests
TESTDIR = $(ROOTOPTPKG)/tests/select
ROOTBINDIR = $(ROOTOPTPKG)/bin

PROGS= select_test

CSTD= $(CSTD_GNU99)

select_test: select_test.c
	$(LINK64.c) -o $@ select_test.c $(LDLIBS64)
	$(POST_PROCESS)

SCRIPTS=select.sh
CMDS = $(PROGS:%=$(TESTDIR)/%) $(SCRIPTS:%=$(TESTDIR)/%)

$(SCRIPTS) $(CMDS) := FILEMODE = 0555

$(CMDS): $(TESTDIR) $(PROGS)

all: $(PROGS)

clean:

clobber: clean
	-$(RM) $(PROGS)

install: all $(CMDS)

lint:

$(ROOTBINDIR):
	$(INS.dir)

$(ROOTBINDIR)/%: %
	$(INS.file)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %
	$(INS.file)

.KEEP_STATE:
