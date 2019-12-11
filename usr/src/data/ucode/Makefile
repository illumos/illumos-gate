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

include	$(SRC)/data/Makefile.data

ROOTUCODEPATH = $(ROOT)/platform/i86pc/ucode
ROOTAMDDIR = $(ROOTUCODEPATH)/AuthenticAMD
ROOTINTELDIR = $(ROOTUCODEPATH)/GenuineIntel

AMD_FILES :sh= (cd amd; print *)
INTEL_FILES :sh= (cd intel; print *-*)
include $(SRC)/data/ucode/Makefile.links

ROOTAMDFILES = $(AMD_FILES:%=$(ROOTAMDDIR)/%)
ROOTINTELFILES = $(INTEL_FILES:%=$(ROOTINTELDIR)/%)
ROOTINTELLINKS = $(INTEL_LINKS:%=$(ROOTINTELDIR)/%)

$(ROOTAMDFILES) := FILEMODE = 444
$(ROOTINTELFILES) := FILEMODE = 444

all:

install: $(ROOTAMDFILES) $(ROOTINTELFILES) $(ROOTINTELLINKS)

clean:

$(ROOTUCODEPATH):
	$(INS.dir)

$(ROOTINTELDIR) $(ROOTAMDDIR): $(ROOTUCODEPATH)
	$(INS.dir)

$(ROOTAMDDIR)/%: amd/% $(ROOTAMDDIR)
	$(INS.file)

$(ROOTINTELDIR)/%: intel/% $(ROOTINTELDIR)
	$(INS.file)

include	$(SRC)/data/Makefile.targ
