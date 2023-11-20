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
# Copyright 2023 Oxide Computer Company
#

PROG= spd

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../Makefile.ctf

ROOTCMDDIR = $(ROOTLIB)/spd
CFLAGS += $(CCVERBOSE)
LDLIBS += -lnvpair -ljedec
CTF_MODE = link

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTCMD)

clean:

include ../Makefile.targ
