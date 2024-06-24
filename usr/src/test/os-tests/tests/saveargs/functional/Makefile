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
# Copyright 2012, Richard Lowe.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/Makefile.master.64
include	$(SRC)/cmd/Makefile.ctf

CTF_MODE = link

.KEEP_STATE:

PROG = \
	align \
	basic \
	big-struct-ret \
	big-struct-ret-and-spill \
	functional \
	small-struct-ret \
	small-struct-ret-and-spill \
	stack-spill

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/saveargs/functional

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all: $(PROG)

install: $(CMDS)

clean:
	$(RM) $(PROG)

clobber: clean

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
