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

PROG = clock_lock
PROG32 = $(PROG:%=%.32)
PROG64 = $(PROG:%=%.64)

OBJS =	clock_lock.o \
	clock_lock_cond.o \
	clock_lock_mutex.o \
	clock_lock_rwlock.o \
	clock_lock_sem.o

OBJS32 = $(OBJS:%.o=%.32.o)
OBJS64 = $(OBJS:%.o=%.64.o)

ROOTOPTDIR = $(ROOT)/opt/libc-tests/tests
ROOTOPTPROGS =	$(PROG32:%=$(ROOTOPTDIR)/%) \
		$(PROG64:%=$(ROOTOPTDIR)/%)

include $(SRC)/cmd/Makefile.cmd

CSTD = $(GNU_C99)
CPPFLAGS += -D_REENTRANT

.KEEP_STATE:

all: $(PROG32) $(PROG64)

install: $(ROOTOPTPROGS) $(ROOTOPTDIR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTDIR)/%: %
	$(INS.file)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.32: $(OBJS32)
	$(LINK.c) -o $@ $(OBJS32) $(LDLIBS)
	$(POST_PROCESS)

%.64.o: %.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)

%.64: $(OBJS64)
	$(LINK64.c) -o $@ $(OBJS64) $(LDLIBS64)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS32) $(OBJS64)

clobber: clean
	$(RM) $(PROGS32) $(PROGS64)
