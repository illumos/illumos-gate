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
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/files

PROGS = test0 \
	test1 \
	test2 \
	test3 \
	test4 \
	test5 \
	test6 \
	test7 \
	gout0 \
	gout1 \
	gout2 \
	gout3 \
	gout4 \
	gout5 \
	gout6 \
	gout7 \
	gout8 \
	gout9 \
	gout10 \
	gout11 \
	gout12 \
	gout13 \
	gout14 \
	gout15 \
	gout16 \
	gout17 \
	gout18 \
	gout19 \
	gout20 \
	gout21 \
	gout22 \
	gout23 \
	gout24 \
	gout25 \
	gout26 \
	gout27 \
	gout28 \
	gout29 \
	gout30 \
	gout31 \
	gout32 \
	gout33 \
	gout34 \
	gout35 \
	gout36 \
	gout37 \
	gout38 \
	gout39 \
	gout40 \
	gout41 \
	gout42 \
	gout43 \
	gout44 \
	gout45 \
	gout46 \
	gout47 \
	gout48 \
	gout49 \
	gout50 \
	gout51 \
	gout52 \
	gout53 \
	gout54 \
	gout55 \
	gout56 \
	gout57 \
	gout58 \
	gout59 \
	gout60 \
	gout61 \
	gout62

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0444

all lint clean clobber:

install: $(CMDS)

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
