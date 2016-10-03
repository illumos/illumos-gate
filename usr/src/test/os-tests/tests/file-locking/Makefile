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
# Copyright 2016 Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

UTILS = util.c

PROGS = \
	runtests \
	acquire-lock

C99MODE = -xc99=%all

SRCS = $(PROGS:%=%.c) $(UTILS)
LINTS = $(SRCS:%.c=%.ln)
PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

runtests.32 :=	LDLIBS += -lgen
runtests.64 :=	LDLIBS64 += -lgen

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests/file-locking
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTDIR)/%) \
	$(PROGS64:%=$(ROOTOPTDIR)/%)

all     :=      TARGET = all
install :=      TARGET = install
clean   :=      TARGET = clean
clobber :=      TARGET = clobber
lint    :=      TARGET = lint

.KEEP_STATE:

install: $(ROOTOPTPROGS)

all: $(PROGS32) $(PROGS64)

lint: $(LINTS)

clean:
	-rm $(PROGS32) $(PROGS64)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTDIR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTDIR)/%: %
	$(INS.file)

$(ROOTOPTDIR)/%: %.ksh
	$(INS.rename)

%.64: %.c
	$(LINK64.c) -o $@ $< $(UTILS) $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.c
	$(LINK.c) -o $@ $< $(UTILS) $(LDLIBS)
	$(POST_PROCESS)

clobber:
	$(RM) $(PROGS32) $(PROGS64)

FRC:
