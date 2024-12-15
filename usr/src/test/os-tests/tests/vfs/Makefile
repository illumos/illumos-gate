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

PROGS = statvfs \
	syncfs

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

OBJS32 = $(PROGS:%=%.32.o)
OBJS64 = $(PROGS:%=%.64.o)

ROOTOPTDIR =	$(ROOT)/opt/os-tests/tests
ROOTOPTPROGS =	$(PROGS32:%=$(ROOTOPTDIR)/%) \
		$(PROGS64:%=$(ROOTOPTDIR)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

CSTD = $(CSTD_GNU17)
CTF_MODE = link

statvfs.32	:= CPPFLAGS += -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
statvfs.32	:= LDLIBS += -lsocket
statvfs.64	:= LDLIBS64 += -lsocket

syncfs.32	:= CPPFLAGS += -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
syncfs.32	:= LDLIBS += -lsocket
syncfs.64	:= LDLIBS64 += -lsocket

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS)

clean:
	$(RM) $(OBJS32) $(OBJS64)

$(PROGS32): $(OBJS32)
$(PROGS64): $(OBJS64)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTDIR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTDIR)/%: %
	$(INS.file)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.64.o: %.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)

%.64: %.64.o
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.32.o
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

clobber: clean
	$(RM) $(PROGS32) $(PROGS64)

FRC:
