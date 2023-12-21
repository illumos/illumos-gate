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

DATAFILES :sh= (print *.*)

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/cpio
DATADIR = $(TESTDIR)/files

DATAS = $(DATAFILES:%=$(DATADIR)/%)
$(DATAS) := FILEMODE = 0444

all clean clobber:

install: all $(DATAS)

$(DATADIR): $(TESTDIR)
$(DATAS): $(DATADIR)

$(TESTDIR) $(DATADIR):
	$(INS.dir)

$(DATADIR)/%: %
	$(INS.file)
