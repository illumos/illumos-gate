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
# Copyright (c) 2012, 2015 by Delphix. All rights reserved.
# Copyright 2016, OmniTI Computer Consulting, Inc. All rights reserved.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/zfs-tests
TESTDIR = $(ROOTOPTPKG)/tests/functional/cli_root/zfs_receive

PROGS = cleanup \
	setup \
	zfs_receive_001_pos \
	zfs_receive_002_pos \
	zfs_receive_003_pos \
	zfs_receive_004_neg \
	zfs_receive_005_neg \
	zfs_receive_006_pos \
	zfs_receive_007_neg \
	zfs_receive_008_pos \
	zfs_receive_009_neg \
	zfs_receive_010_pos \
	zfs_receive_011_pos \
	zfs_receive_012_pos \
	zfs_receive_013_pos

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all lint clean clobber:

install: $(CMDS)

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)
