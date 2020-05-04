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
include $(SRC)/cmd/Makefile.cmd

ROOTOPTPKG = $(ROOT)/opt/net-tests
TESTDIR = $(ROOTOPTPKG)/tests/forwarding

PROG = \
	ip_forwarding \
	ip_fwd_suite \
	ip_fwd_001 \
	ip_fwd_002 \
	ip_fwd_003 \
	ip_fwd_004 \
	ip_fwd_005 \
	ip_fwd_006 \
	ip_fwd_007 \
	ip_fwd_008 \
	ip_fwd_009 \
	ip_fwd_010 \
	ip_fwd_011 \
	ip_fwd_012 \
	ip_fwd_013 \
	ip_fwd_014 \
	ip_fwd_015 \
	ip_fwd_016 \
	ip_fwd_017 \
	ip_fwd_018 \
	ip_fwd_019 \
	ip_fwd_020

DOC = $(TESTDIR)/README

CMDS = $(PROG:%=$(TESTDIR)/%)
FILEMODE=0444
$(CMDS) := FILEMODE = 0555

include $(SRC)/test/Makefile.com

install: $(CMDS) $(DOC)

clobber: clean
	$(RM) $(CMDS) $(DOC)

$(CMDS) $(DOC): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)
