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
# Copyright 2021 Oxide Computer Company
#

PROGS = dumper

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)
ALLOBJS = $(PROGS32:%=%.o) $(PROGS64:%=%.o)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf
include ../Makefile.com

ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTCORE)/%) \
	$(PROGS64:%=$(ROOTOPTCORE)/%)

LDLIBS += -lproc -L$(ROOTOPTCORE) -ldumper -R\$$ORIGIN
LDLIBS64 += -lproc -L$(ROOTOPTCORE)/$(MACH64) -ldumper -R\$$ORIGIN/$(MACH64)

#
# We need to explicitly set the objects for some of our programs with
# CTF so that way we can make sure that we have what we need.
#
dumper.32	:= OBJS = dumper.32.o
dumper.64	:= OBJS = dumper.32.o

#
# This is admittedly, a bit gross. In particular we need to make sure
# that we have debug information in the following programs.
#
STRIP_STABS = /bin/true

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS)

clean:

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTCORE)

FRC:

include ../Makefile.targ
