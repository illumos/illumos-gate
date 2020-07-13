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
# Copyright 2020 Oxide Computer Company
#

PROGS = \
	ksensor_basic \
	ksensor_err \
	ksensor_sread

SCRIPTS = \
	ksensor_init \
	ksensor_fini \
	ksensor_stress \
	ksensor_unload

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTKSENSOR = $(ROOTOPTDIR)/ksensor
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTKSENSOR)/%) \
	$(PROGS64:%=$(ROOTOPTKSENSOR)/%) \
	$(SCRIPTS:%=$(ROOTOPTKSENSOR)/%)

include $(SRC)/cmd/Makefile.cmd

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS)

clean:

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTKSENSOR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTKSENSOR): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTKSENSOR)/%: %
	$(INS.file)

$(ROOTOPTKSENSOR)/%: %.ksh
	$(INS.rename)

%.64: %.c
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

clobber:
	$(RM) $(PROGS32) $(PROGS64)

FRC:
