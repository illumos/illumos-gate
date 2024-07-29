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
# Copyright 2024 Oxide Computer Company
#

include $(SRC)/Makefile.master

CMDS = \
	libproctest

ROOTOPTPKG = $(ROOT)/opt/libproc-tests
ROOTCMDDIR = $(ROOTOPTPKG)/bin

ROOTCMDS = $(CMDS:%=$(ROOTCMDDIR)/%)
$(ROOTCMDS) := FILEMODE = 0555

all:

install: $(ROOTCMDS)

clean:

clobber:

$(ROOTCMDS): $(ROOTCMDDIR)

$(ROOTCMDDIR):
	$(INS.dir)

$(ROOTCMDDIR)/%: %.ksh
	$(INS.rename)
