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
# Copyright 2019 Joyent, Inc.
#
include $(SRC)/Makefile.master

SRCS = default.run
ROOTOPTPKG = $(ROOT)/opt/net-tests
RUNFILES = $(ROOTOPTPKG)/runfiles
CMDS = $(SRCS:%=$(RUNFILES)/%)
$(CMDS) := FILEMODE = 0444

include $(SRC)/test/Makefile.com

all: $(SRCS)

install: $(CMDS)

clobber: clean
	$(RM) $(CMDS)

$(CMDS): $(RUNFILES) $(SRCS)

$(RUNFILES):
	$(INS.dir)

$(RUNFILES)/%: %
	$(INS.file)
