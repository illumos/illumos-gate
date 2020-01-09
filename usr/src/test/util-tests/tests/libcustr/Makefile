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

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/libcustr

PROGS = custr_remove custr_trunc

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

LDLIBS += -lcustr

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
