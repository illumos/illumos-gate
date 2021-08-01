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

SCRIPTS = core_prereqs coretests

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf
include ../Makefile.com

ROOTOPTPROGS = $(SCRIPTS:%=$(ROOTOPTCORE)/%)

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS)

$(ROOTOPTPROGS): $(ROOTOPTCORE)

clean:

FRC:

include ../Makefile.targ
