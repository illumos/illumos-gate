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

PROG = secmapper
OBJS = secmapper.o

#
# These are so the common makefile targets will clean things up.
#
ALLOBJS = $(OBJS)
PROGS64 = $(PROG)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include ../Makefile.com

ROOTOPTPROGS = $(PROG:%=$(ROOTOPTCORE)/%)

LDLIBS += -lproc -lelf
CSTD = $(CSTD_GNU17)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: $(ROOTOPTPROGS)

$(ROOTOPTPROGS): $(ROOTOPTCORE) $(PROG)

FRC:

include ../Makefile.targ
