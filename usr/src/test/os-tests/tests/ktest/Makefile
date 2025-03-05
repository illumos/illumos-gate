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

SCRIPTS = \
	stream_ktest \
	mac_ktest \
	ktest_ktest

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTKTEST = $(ROOTOPTDIR)/ktest
ROOTOPTPROGS = $(SCRIPTS:%=$(ROOTOPTKTEST)/%)

include $(SRC)/cmd/Makefile.cmd

.KEEP_STATE:

all:

install: $(ROOTOPTPROGS)

clean:

clobber:

$(ROOTOPTPROGS): $(ROOTOPTKTEST)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTKTEST): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTKTEST)/%: %.ksh
	$(INS.rename)
