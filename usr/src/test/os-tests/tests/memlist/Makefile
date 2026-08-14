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
# Copyright 2026 Oxide Computer Company
#

PROGS = \
	memlist_test

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

COMOBJS = memlist_new.o
COMOBJS32 = $(COMOBJS:.o=.32.o)
COMOBJS64 = $(COMOBJS:.o=.64.o)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTMEMLIST = $(ROOTOPTDIR)/memlist
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTMEMLIST)/%) $(PROGS64:%=$(ROOTOPTMEMLIST)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

CSTD = $(CSTD_GNU17)

CTF_MODE = link

CPPFLAGS.first += -I$(SRC)/lib/libfakekernel/common -D_FAKE_KERNEL
CPPFLAGS += -I$(SRC)/uts/common
CPPFLAGS += -DDEBUG

LDLIBS += -lfakekernel
LDLIBS64 += -lfakekernel

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS)

clean:
	$(RM) $(COMOBJS32) $(COMOBJS64)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTMEMLIST)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTMEMLIST): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTMEMLIST)/%: %
	$(INS.file)

%.32: %.c $(COMOBJS32)
	$(LINK.c) -o $@ $^ $(LDLIBS)
	$(POST_PROCESS)

%.64: %.c $(COMOBJS64)
	$(LINK64.c) -o $@ $^ $(LDLIBS64)
	$(POST_PROCESS)

memlist_new.32.o: $(SRC)/uts/common/os/memlist_new.c
	$(COMPILE.c) -o $@ $(SRC)/uts/common/os/memlist_new.c
	$(POST_PROCESS_O)

memlist_new.64.o: $(SRC)/uts/common/os/memlist_new.c
	$(COMPILE64.c) -o $@ $(SRC)/uts/common/os/memlist_new.c
	$(POST_PROCESS_O)

clobber: clean
	$(RM) $(PROGS32) $(PROGS64)

FRC:
