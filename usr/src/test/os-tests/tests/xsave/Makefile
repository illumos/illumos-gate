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
	bad_xregs \
	fpregs \
	fpregs_xbv \
	proc_xregs_set \
	setcontext_replace \
	setcontext_restore \
	swapcontext_extd \
	signal_restore \
	xregs_dump \
	xregs_roundtrip \
	xregs_set \
	xsave_baducontext \
	xsu_hwtype

SCRIPTS = mdb_xregs proc_writes xsave_baducontext

DATAFILES = \
	mdb_xregs.ymm.32 \
	mdb_xregs.ymm.64 \
	mdb_xregs.zmm.32 \
	mdb_xregs.zmm.64 \
	proc_writes.fpregs.ymm.32 \
	proc_writes.fpregs.ymm.64 \
	proc_writes.fpregs.zmm.32 \
	proc_writes.fpregs.zmm.64 \
	proc_writes.xregs.ymm.32 \
	proc_writes.xregs.ymm.64 \
	proc_writes.xregs.zmm.32 \
	proc_writes.xregs.zmm.64

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTXSAVE = $(ROOTOPTDIR)/xsave
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTXSAVE)/%) \
	$(PROGS64:%=$(ROOTOPTXSAVE)/%) \
	$(SCRIPTS:%=$(ROOTOPTXSAVE)/%)
ROOTOPTDATADIR = $(ROOTOPTXSAVE)/data
ROOTOPTDATA = $(DATAFILES:%=$(ROOTOPTDATADIR)/%)

COMMOBJS32 = xsave_util.32.o xsave_asm32.32.o
COMMOBJS64 = xsave_util.64.o xsave_asm64.64.o

OBJS32 = $(COMMOBJS32) $(PROGS:%=%.32.o)
OBJS64 = $(COMMOBJS64) $(PROGS:%=%.64.o)

#
# To simplify things we always link in the support files to programs
# even though in some case (e.g. xsave_baducontext) they aren't needed.
# This also drives a requirement that everything links against libproc
# (seen below).
#
EXTRA_OBJS32 = $(COMMOBJS32)
EXTRA_OBJS64 = $(COMMOBJS64)

include $(SRC)/cmd/Makefile.cmd

#
# These are required to get COMPILE.s to work as Makefile.master puts
# some things in AS_CPPFLAGS, but not what we need to make it work.
#
AS_CPPFLAGS += -D_ASM

$(ROOTOPTDATA) := FILEMODE = 0444

LDLIBS += -lproc
LDLIBS64 += -lproc

CSTD = $(CSTD_GNU17)

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS) $(ROOTOPTDATA)

clean:
	$(RM) $(OBJS32) $(OBJS64)

$(PROGS32): $(OBJS32)
$(PROGS64): $(OBJS64)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTXSAVE)
$(ROOTOPTDATA): $(ROOTOPTDATADIR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTXSAVE): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTDATADIR): $(ROOTOPTXSAVE)
	$(INS.dir)

$(ROOTOPTXSAVE)/%: %
	$(INS.file)

$(ROOTOPTXSAVE)/%: %.ksh
	$(INS.rename)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.64.o: %.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)

%.32.o: %.S
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_S_0)

%.64.o: %.S
	$(COMPILE64.s) -o $@ $<
	$(POST_PROCESS_S_0)

%.64: %.64.o
	$(LINK64.c) -o $@ $< $(LDLIBS64) $(EXTRA_OBJS64)
	$(POST_PROCESS)

%.32: %.32.o
	$(LINK.c) -o $@ $< $(LDLIBS) $(EXTRA_OBJS32)
	$(POST_PROCESS)

clobber: clean
	$(RM) $(PROGS32) $(PROGS64)

FRC:
