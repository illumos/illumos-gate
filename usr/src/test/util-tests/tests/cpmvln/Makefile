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

PROGS = mkobj checker
SCRIPTS = overwrite

ROOTOPTDIR = $(ROOT)/opt/util-tests/tests
ROOTOPTCML = $(ROOTOPTDIR)/cpmvln
ROOTOPTPROGS = $(PROGS:%=$(ROOTOPTCML)/%) $(SCRIPTS:%=$(ROOTOPTCML)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/Makefile.ctf

CSTD = $(CSTD_GNU17)
CTF_MODE = link
mkobj := LDLIBS += -lsocket

.KEEP_STATE:

all: $(PROGS)

install: $(ROOTOPTPROGS)

clean:
	$(RM) *.o

$(ROOTOPTPROGS): $(PROGS) $(ROOTOPTCML)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTCML): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTCML)/%: %
	$(INS.file)

$(ROOTOPTCML)/%: %.ksh
	$(INS.rename)

clobber: clean
	$(RM) $(PROGS)

FRC:
