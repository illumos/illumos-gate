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
# Copyright 2024 RackTop Systems, Inc.
#
include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd

ROOTOPTPKG = $(ROOT)/opt/libsec-tests
TESTDIR = $(ROOTOPTPKG)/tests/fromtext

PROG = \
	acl_fromtext_0 \
	acl_fromtext_1 \
	acl_fromtext_2 \
	acl_fromtext_3 \
	acl_fromtext_4 \
	acl_fromtext_5 \
	acl_fromtext_6 \
	acl_fromtext_7

CMDS = $(PROG:%=$(TESTDIR)/%)
FILEMODE=0444
$(CMDS) := FILEMODE = 0555

include $(SRC)/test/Makefile.com

install: $(CMDS)

clobber: clean
	$(RM) $(CMDS)

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)
