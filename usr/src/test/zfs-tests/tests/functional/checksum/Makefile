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
# Copyright (c) 2015 by Delphix. All rights reserved.
#

.PARALLEL: $(SUBDIRS)

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/zfs-tests
TESTDIR = $(ROOTOPTPKG)/tests/functional/checksum

SCRIPTS = run_edonr_test \
	run_sha2_test \
	run_skein_test

CMDS = $(SCRIPTS:%=$(TESTDIR)/%)
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

SUBDIRS = edonr \
	sha2 \
	skein

include $(SRC)/test/Makefile.com
