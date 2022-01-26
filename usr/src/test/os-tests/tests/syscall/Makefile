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
# Copyright 2020 Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROGS = fchmodat open

CSTD = $(CSTD_GNU99)

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/syscall

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)
CMDS = $(PROGS32) $(PROGS64)
$(CMDS) := FILEMODE = 0555

TESTDIRPROGS = $(PROGS32:%=$(TESTDIR)/%) \
	$(PROGS64:%=$(TESTDIR)/%)

all: $(PROGS32) $(PROGS64)

install: all $(TESTDIR) $(TESTDIRPROGS)

clobber: clean

clean:
	-$(RM) $(CMDS)

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
