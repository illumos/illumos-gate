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
	execvpe-test

DATA = \
	execvpe-script \
	execvpe-noperm

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTEXECVPE = $(ROOTOPTDIR)/execvpe
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTEXECVPE)/%) \
	$(PROGS64:%=$(ROOTOPTEXECVPE)/%) \
	$(SCRIPTS:%=$(ROOTOPTEXECVPE)/%)
ROOTOPTDATA = $(DATA:%=$(ROOTOPTEXECVPE)/%)

$(ROOTOPTEXECVPE)/execvpe-noperm := FILEMODE = 0444

include $(SRC)/cmd/Makefile.cmd

CSTD = $(CSTD_GNU17)
.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS) $(ROOTOPTDATA)

clean:
	$(RM) $(OBJS32) $(OBJS64)

$(PROGS32): $(OBJS32)
$(PROGS64): $(OBJS64)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTEXECVPE)
$(ROOTOPTDATA): $(ROOTOPTEXECVPE)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTEXECVPE): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTEXECVPE)/%: %
	$(INS.file)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.64.o: %.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)

%.64: %.64.o
	$(LINK64.c) -o $@ $< $(LDLIBS64) $(EXTRA_OBJS64)
	$(POST_PROCESS)

%.32: %.32.o
	$(LINK.c) -o $@ $< $(LDLIBS) $(EXTRA_OBJS32)
	$(POST_PROCESS)

clobber: clean
	$(RM) $(PROGS32) $(PROGS64)

FRC:
