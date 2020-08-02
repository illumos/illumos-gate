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
include $(SRC)/test/Makefile.com

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/files/grep

PROGS = test0 \
	test1 \
	test2 \
	test3 \
	test4 \
	test5 \
	test6 \
	test7 \
	test.lL.0 \
	test.lL.1 \
	gout.t1.0 \
	gout.t1.1 \
	gout.t1.2 \
	gout.t1.3 \
	gout.t1.4 \
	gout.t1.5 \
	gout.t1.6 \
	gout.t1.7 \
	gout.t1.8 \
	gout.t1.9 \
	gout.t1.10 \
	gout.t1.11 \
	gout.t1.12 \
	gout.t1.13 \
	gout.t1.14 \
	gout.t1.15 \
	gout.t1.16 \
	gout.t1.17 \
	gout.t1.18 \
	gout.t1.19 \
	gout.t1.20 \
	gout.t1.21 \
	gout.t1.22 \
	gout.t1.23 \
	gout.t1.24 \
	gout.t1.25 \
	gout.t1.26 \
	gout.t1.27 \
	gout.t1.28 \
	gout.t1.29 \
	gout.t1.30 \
	gout.t1.31 \
	gout.t1.32 \
	gout.t1.33 \
	gout.t1.34 \
	gout.t1.35 \
	gout.t1.36 \
	gout.t1.37 \
	gout.t1.38 \
	gout.t1.39 \
	gout.t1.40 \
	gout.t1.41 \
	gout.t1.42 \
	gout.t1.43 \
	gout.t1.44 \
	gout.t1.45 \
	gout.t1.46 \
	gout.t1.47 \
	gout.t1.48 \
	gout.t1.49 \
	gout.t1.50 \
	gout.t1.51 \
	gout.t1.52 \
	gout.t1.53 \
	gout.t1.54 \
	gout.t1.55 \
	gout.t1.56 \
	gout.t1.57 \
	gout.t1.58 \
	gout.t1.59 \
	gout.t1.60 \
	gout.t1.61 \
	gout.t1.62 \
	gout.t2.0 \
	gout.t3.0 \
	gout.t3.1 \
	gout.t3.2 \
	gout.t4.0 \
	gout.t4.1 \
	gout.t5.0 \
	gout.t5.1 \
	gout.t6.0 \
	gout.t6.1 \
	gout.t6.2 \
	gout.t6.3 \
	gout.t6.4 \
	gout.t6.5 \
	gout.t6.6 \
	gout.t6.7 \
	gout.t6.8 \
	gout.t6.9 \
	gout.t6.10 \
	gout.t6.11 \
	gout.t6.12 \
	gout.t6.13 \
	gout.t6.14 \
	gout.t6.15 \
	gout.t6.16 \
	gout.t6.17 \
	gout.t6.18 \
	gout.t6.19 \
	testnl

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0444

all lint clean clobber:

install: $(CMDS)

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
