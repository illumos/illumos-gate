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
# Copyright (c) 2016 by Delphix. All rights reserved.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/zfs-tests
TESTDIR = $(ROOTOPTPKG)/tests/functional/channel_program/synctask_core

KSHFILES :sh= ls *.ksh
PROGS = $(KSHFILES:.ksh=)
FILES :sh= ls *.zcp *.out *.err 2>/dev/null; true

INSTPROGS = $(PROGS:%=$(TESTDIR)/%)
INSTFILES = $(FILES:%=$(TESTDIR)/%)

$(INSTPROGS) := FILEMODE = 0555
$(INSTFILES) := FILEMODE = 0444

all lint clean clobber:

install: $(INSTPROGS) $(INSTFILES)

$(INSTPROGS): $(TESTDIR)
$(INSTFILES): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

$(TESTDIR)/%: %
	$(INS.file)
