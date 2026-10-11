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
# Copyright 2026 Jason King
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests

PROGS = libofmt_print
PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

ROOTOPTPROGS = $(PROGS32:%=$(TESTDIR)/%) \
	$(PROGS64:%=$(TESTDIR)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

CMDS = $(PROGS32:%=$(TESTDIR)/%) $(PROGS64:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

LDLIBS += -lofmt
LDLIBS64 += -lofmt

CSTD = $(CSTD_GNU17)

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: all $(ROOTOPTPROGS)

clobber: clean
	-$(RM) $(PROGS32) $(PROGS64)

clean:

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

%.64: %.c
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)
