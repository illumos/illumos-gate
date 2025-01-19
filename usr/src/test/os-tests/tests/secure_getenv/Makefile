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
# Copyright 2025 Oxide Computer Company
#

PROGS = secure_getenv checker

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTTEST = $(ROOTOPTDIR)/secure_getenv
ROOTOPTPROGS =	$(PROGS:%=$(ROOTOPTTEST)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/Makefile.ctf

CSTD = $(CSTD_GNU17)
CPPFLAGS += -D_REENTRANT
CTF_MODE = link

.KEEP_STATE:

all: $(PROGS)

install: $(ROOTOPTPROGS)

$(ROOTOPTPROGS): $(PROGS) $(ROOTOPTTEST)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTTEST): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTTEST)/%: %
	$(INS.file)

clean:

clobber: clean
	$(RM) $(PROGS)
