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
# Copyright (c) 2013 by Delphix. All rights reserved.
# Copyright 2014 Nexenta Systems, Inc. All rights reserved.
# Copyright 2020 Peter Tribble.
# Copyright 2020 Oxide Computer Company
#

include $(SRC)/cmd/Makefile.cmd

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/files/svr4pkg/data

DIRS = a b
FILES = a/file1.txt b/file2.txt
IDIRS = $(DIRS:%=$(TESTDIR)/%)
IFILES = $(FILES:%=$(TESTDIR)/%)

$(IFILES) := FILEMODE = 0444

all clean clobber:

install: $(IDIRS) $(IFILES)

$(CMDS): $(TESTDIR)

$(IDIRS):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

include $(SRC)/test/Makefile.com
