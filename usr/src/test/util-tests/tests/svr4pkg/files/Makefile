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
TESTDIR = $(ROOTOPTPKG)/tests/files/svr4pkg

DIRS = data
IDIRS = $(DIRS:%=$(TESTDIR)/%)

all clean clobber:

install: $(IDIRS)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.dir)

SUBDIRS = data

include $(SRC)/test/Makefile.com
