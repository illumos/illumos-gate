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

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/mdb/progs
PROGS = \
	anon		\
	bitfields	\
	number_symbol

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/Makefile.ctf
include $(SRC)/test/Makefile.com

CTF_MODE = link

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555
CSTD = $(CSTD_GNU17)

all: $(PROGS)

install: all $(CMDS) $(OUTFILES)

clobber: clean
	-$(RM) $(PROGS)

clean:

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

%: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)
