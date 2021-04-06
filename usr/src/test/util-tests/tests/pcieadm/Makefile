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

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ROOTOPTPKG = $(ROOT)/opt/util-tests/tests
ROOTOPTPCI = $(ROOT)/opt/util-tests/tests/pci
PROG = pcieadmtest
DATAFILES = bridge.pci igb.pci \
	header0-basic.out \
	header0-basic-L.out \
	header0-basic-LH.out \
	header0-basic-n.out \
	header0-parse.out \
	igb-ltr.out \
	igb-ltr-p.out \
	bridge-ht.out \
	bridge-ht-p.out \
	bridge-ht.msi-p.out \
	bridge-ht.msi.command-p.out \
	bridge-efilt.out \
	bridge-efilt-p.out

ROOTPROG = $(PROG:%=$(ROOTOPTPKG)/%)
ROOTDATA = $(DATAFILES:%=$(ROOTOPTPCI)/%)
$(ROOTDATA) := FILEMODE = 0444

all:

install: $(ROOTDATA) $(ROOTPROG)

clobber: clean

clean:

$(ROOTOPTPKG):
	$(INS.dir)

$(ROOTOPTPCI): $(ROOTOPTPKG)
	$(INS.dir)

$(ROOTOPTPCI)/%: % $(ROOTOPTPCI)
	$(INS.file)

$(ROOTOPTPKG)/%: %.ksh $(ROOTOPTPKG)
	$(INS.rename)
