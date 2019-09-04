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
# Copyright 2019 Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROGS += ldt badseg_exec badseg

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/i386
ROOTOPTPROGS = $(PROGS:%=$(TESTDIR)/%)

CSTD = $(CSTD_GNU99)

# for badseg_exec
COPTFLAG =

all: $(PROGS)

install: all $(ROOTOPTPROGS)

clobber: clean
	-$(RM) $(PROGS)

clean:

$(ROOTOPTPROGS): $(TESTDIR) $(PROGS)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
