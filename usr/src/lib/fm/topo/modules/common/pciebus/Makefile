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

include $(SRC)/lib/Makefile.lib
include $(SRC)/lib/fm/Makefile.lib

HDRDIR =	.
FMHDRS =	topo_pcie.h

all install clean clobber:

install_h: $(ROOTFMHDRS)

check: $(CHECKHDRS)

$(ROOTFMHDRDIR)/%: %
	$(INS.file)
