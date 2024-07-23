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
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2017 Gordon W. Ross
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

# These test programs are built as both 32- and 64-bit variants
PROGDA = rights recvmsg

PROG =	conn dgram drop_priv nosignal sockpair \
	$(PROGDA:%=%.32) $(PROGDA:%=%.64) \
	so_protocol

LDLIBS += -lsocket
LDLIBS64 += -lsocket

CSTD = $(CSTD_GNU99)
CPPFLAGS += -D_XOPEN_SOURCE=600 -D__EXTENSIONS__

# needs work
SMOFF += all_func_returns

nosignal := LDLIBS += -lnsl
rights.32 := LDLIBS += -lproc
rights.64 := LDLIBS64 += -lproc

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/sockfs

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all: $(PROG)

install: $(CMDS)

clobber: clean
	-$(RM) $(PROG)

clean:

$(CMDS): $(TESTDIR) $(PROG)

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
