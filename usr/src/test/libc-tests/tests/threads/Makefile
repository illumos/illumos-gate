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
# Copyright 2016 Joyent, Inc.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/libc-tests
TESTDIR = $(ROOTOPTPKG)/tests

PROGS = pthread_attr_get_np

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

CPPFLAGS += -D_REENTRANT

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all: $(PROGS)

install: all $(CMDS)

lint:

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) *.o

$(CMDS): $(TESTDIR) $(PROGS)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %
	$(INS.file)
