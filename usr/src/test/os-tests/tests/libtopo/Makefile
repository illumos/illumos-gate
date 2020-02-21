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

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/libtopo

PROGS = digraph-test

XML =	digraph-test-in.xml \
	digraph-test-in-badscheme.xml \
	digraph-test-in-badnum.xml \
	digraph-test-in-badedge.xml \
	digraph-test-in-badelement.xml

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

LDLIBS += -L$(ROOT)/usr/lib/fm -ltopo -R/usr/lib/fm
CFLAGS += -I$(SRC)/lib/fm/topo/libtopo/
CSTD= $(CSTD_GNU99)

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

FILES = $(XML:%=$(TESTDIR)/%)
$(FILES) := FILEMODE = 0444

all: $(PROGS)

install: all $(CMDS) $(FILES)

clobber: clean
	-$(RM) $(PROGS) $(FILES)

clean:
	-$(RM) *.o

$(CMDS): $(TESTDIR) $(PROGS)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
