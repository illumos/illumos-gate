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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2023 Oxide Computer Company
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/

PROGS = libjedec_test libjedec_temp libjedec_spd

LINTS = $(PROGS:%=%.ln)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

LDLIBS += -ljedec
libjedec_spd	:= LDLIBS += -lnvpair
CSTD = $(GNU_C99)

all: $(PROGS)

install: all $(CMDS) $(OUTFILES)

lint:

clobber: clean
	-$(RM) $(PROGS) $(LINTS)

clean:

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

%: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)
