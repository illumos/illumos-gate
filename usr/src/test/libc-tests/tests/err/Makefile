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
# Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
#

include $(SRC)/Makefile.master

ROOTOPTPKG =	$(ROOT)/opt/libc-tests
TESTDIR =	$(ROOTOPTPKG)/tests/err
DATADIR=	$(TESTDIR)/data

PROGS = err
SCRIPTS = err.ksh
DATA :sh= (cd data; print *)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

CMDS =		$(PROGS:%=$(TESTDIR)/%) $(SCRIPTS:%=$(TESTDIR)/%)
TESTDATA=	$(DATA:%=$(DATADIR)/%)

$(CMDS) := FILEMODE = 0555
$(TESTDATA) := FILEMODE = 0444

CSTD = $(CSTD_GNU99)

all: $(PROGS)

install: all $(CMDS) $(TESTDATA)

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) *.o

$(CMDS): $(TESTDIR) $(PROGS)

$(TESTDATA): $(DATADIR)

$(TESTDIR) $(DATADIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(DATADIR)/%:	data/%
	$(INS.file)

