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
# Copyright 2022 Oxide Computer Company
#

include $(SRC)/Makefile.master

SRCS = default.run

OPTPKG = opt/bhyve-tests
ROOTOPTPKG = $(ROOT)/$(OPTPKG)
RUNFILES = $(ROOTOPTPKG)/runfiles

OUTPUTS = $(SRCS:%=$(RUNFILES)/%)
$(OUTPUTS) := FILEMODE = 0444

all: $(SRCS)

install: $(OUTPUTS)

check:
	$(CHECK_TEST_RUNFILES) -T $(OPTPKG) $(SRCS)

clean lint clobber:

$(OUTPUTS): $(RUNFILES) $(SRCS)

$(RUNFILES):
	$(INS.dir)

$(RUNFILES)/%: %
	$(INS.file)
