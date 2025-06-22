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

include $(SRC)/Makefile.master

RUNFILES = \
	destruct.run \
	non-destruct.run \
	unit.run

ROOTOPTPKG = $(ROOT)/opt/nvme-tests
ROOTRUNDIR = $(ROOTOPTPKG)/runfiles

ROOTRUNFILES = $(RUNFILES:%=$(ROOTRUNDIR)/%)
$(ROOTRUNFILES) := FILEMODE = 0444

all: $(SRCS)

install: $(ROOTRUNFILES)

clean:

clobber:

$(ROOTRUNFILES): $(ROOTRUNDIR)

$(ROOTRUNDIR):
	$(INS.dir)

$(ROOTRUNDIR)/%: %
	$(INS.file)
