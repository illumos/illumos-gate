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
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
# Copyright 2016, Joyent, Inc.
#

include $(SRC)/Makefile.master

SRCS = default.run

OPTPKG = opt/os-tests
ROOTOPTPKG = $(ROOT)/$(OPTPKG)
RUNFILES = $(ROOTOPTPKG)/runfiles

CMDS = $(SRCS:%=$(RUNFILES)/%)
$(CMDS) := FILEMODE = 0444

all: $(SRCS)

install: $(CMDS)

clean lint clobber:

check:
	$(CHECK_TEST_RUNFILES) -T $(OPTPKG) $(SRCS)

$(CMDS): $(RUNFILES) $(SRCS)

$(RUNFILES):
	$(INS.dir)

$(RUNFILES)/%: %
	$(INS.file)
