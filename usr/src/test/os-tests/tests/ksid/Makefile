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
# Copyright 2020 Tintri by DDN, Inc. All rights reserved.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG =	ksid.32 ksid.64

LDLIBS += -lfakekernel
LDLIBS64 += -lfakekernel

CSTD = $(CSTD_GNU99)
CPPFLAGS.first += -I$(SRC)/lib/libfakekernel/common -D_FAKE_KERNEL

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/ksid

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
