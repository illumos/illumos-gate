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
# Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

SHFILES = iconv_test

ROOTBIN = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTBIN)/tests

CMDS = $(SHFILES:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all: $(PROG)

$(SHFILES): $(SHFILES).sh
	-$(RM) $(SHFILES)
	$(CP) $(SHFILES).sh $(SHFILES)

install: all $(CMDS)

lint:

clobber: clean
	-$(RM) $(SHFILES)

clean:

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
