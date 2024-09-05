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
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG = multi_test
DATAFILES :sh= (cd regress.multitest.out; print *)
INFILES = multi_words

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/sed
DATADIR = $(TESTDIR)/regress.multitest.out

TESTS = $(PROG:%=$(TESTDIR)/%)
DATAS = $(DATAFILES:%=$(DATADIR)/%) $(INFILES:%=$(TESTDIR)/%)
$(TESTS) := FILEMODE = 0555
$(DATAS) := FILEMODE = 0444

all clean clobber:

install: all $(TESTS) $(DATAS)

$(TESTS): $(TESTDIR) $(PROG).ksh
$(DATAS): $(DATADIR)

$(TESTDIR) $(DATADIR):
	$(INS.dir)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

$(TESTDIR)/%: %
	$(INS.file)

$(DATADIR)/%: regress.multitest.out/%
	$(INS.file)
