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
	ilstr_basic

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

COMOBJS = ilstr.o
COMOBJS32 = $(COMOBJS:.o=.32.o)
COMOBJS64 = $(COMOBJS:.o=.64.o)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTILSTR = $(ROOTOPTDIR)/ilstr
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTILSTR)/%) $(PROGS64:%=$(ROOTOPTILSTR)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

LDLIBS += -lumem
LDLIBS64 += -lumem

CTF_MODE = link

CSTD = $(CSTD_GNU17)

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS)

clean:
	$(RM) $(COMOBJS32) $(COMOBJS64)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTILSTR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTILSTR): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTILSTR)/%: %
	$(INS.file)

%.32: %.c $(COMOBJS32)
	$(LINK.c) -o $@ $^ $(LDLIBS)
	$(POST_PROCESS)

%.64: %.c $(COMOBJS64)
	$(LINK64.c) -o $@ $^ $(LDLIBS64)
	$(POST_PROCESS)

%.32.o: $(SRC)/common/ilstr/%.c
	$(COMPILE.c) $< -o $@
	$(POST_PROCESS_O)

%.64.o: $(SRC)/common/ilstr/%.c
	$(COMPILE64.c) $< -o $@
	$(POST_PROCESS_O)

clobber: clean
	$(RM) $(PROGS32) $(PROGS64)

FRC:
