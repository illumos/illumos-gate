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

PROG= pcieadm

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../Makefile.ctf

CFLAGS += $(CCVERBOSE)
CSTD = $(CSTD_GNU17)
LDLIBS += -ldevinfo -lpcidb -lofmt
OBJS = \
	pcieadm.o \
	pcieadm_bar.o \
	pcieadm_cfgspace.o \
	pcieadm_devs.o \
	bitext.o
ROOTCMDDIR = $(ROOTLIB)/pci

.KEEP_STATE:

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/bitext/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

all: $(PROG)

install: all $(ROOTCMD)

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
