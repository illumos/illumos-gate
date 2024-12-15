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

PROGS = \
	illumos-15031 \
	illumos-15036

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTREGRESSION = $(ROOTOPTDIR)/regression
ROOTOPTPROGS = $(PROGS:%=$(ROOTOPTREGRESSION)/%)

include $(SRC)/cmd/Makefile.cmd

CSTD=$(CSTD_GNU17)

.KEEP_STATE:

all: $(PROGS)

install: $(ROOTOPTPROGS)

clean:

$(ROOTOPTPROGS): $(PROGS) $(ROOTOPTREGRESSION)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTREGRESSION): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTREGRESSION)/%: %
	$(INS.file)

%: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

clobber:
	$(RM) $(PROGS)

FRC:
