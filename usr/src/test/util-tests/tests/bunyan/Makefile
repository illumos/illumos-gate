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
# Copyright (c) 2014 Joyent, Inc.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/bunyan
ROOTBINDIR = $(ROOTOPTPKG)/bin

PROG = btest

SCRIPTS = \
	bunyan

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

OBJS = $(PROG:%=%.o)
SRCS = $(OBJS:%.o=%.c)

CMDS = $(PROG:%=$(ROOTBINDIR)/%) $(SCRIPTS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

LDLIBS += -lbunyan

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(CMDS)

lint:

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(OBJS)

$(CMDS): $(TESTDIR) $(PROG)

$(ROOTBINDIR):
	$(INS.dir)

$(ROOTBINDIR)/%: %
	$(INS.file)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

$(TESTDIR)/%: %
	$(INS.file)
