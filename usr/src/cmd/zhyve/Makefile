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
# Copyright 2024 MNX Cloud, Inc.
#

PROG = zhyve

include ../Makefile.cmd
include ../Makefile.cmd.64

ZHYVE_DIR = $(ROOTLIB)/brand/bhyve

LDFLAGS += -lnvpair

.KEEP_STATE:

all: $(PROG)

$(ZHYVE_DIR)/%: %
	$(INS.file)

install: all $(ZHYVE_DIR) $(ZHYVE_DIR)/$(PROG)

clean:

lint:	lint_PROG

include ../Makefile.targ
