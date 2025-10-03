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
# Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2025 Oxide Computer Company
#

include $(SRC)/data/Makefile.data

ROOTINTELDIR = $(ROOTUCODEPATH)/GenuineIntel
ROOTAMDDIR = $(ROOTUCODEPATH)/AuthenticAMD
ROOTAMDFBDIR = $(ROOTUCODEPATH)/AuthenticAMD/fallback

ROOTINTELFILES = $(INTEL_FILES:%=$(ROOTINTELDIR)/%)
ROOTAMDFILES = $(AMD_FILES:%=$(ROOTAMDDIR)/%)
ROOTAMDFBFILES = $(AMD_FILES:%=$(ROOTAMDFBDIR)/%)

$(ROOTINTELFILES) := FILEMODE = 444
$(ROOTAMDFILES) := FILEMODE = 444
$(ROOTAMDFBFILES) := FILEMODE = 444

$(ROOTUCODEPATH):
	$(INS.dir)

$(ROOTINTELDIR) $(ROOTAMDDIR) $(ROOTAMDFBDIR): $(ROOTUCODEPATH)
	$(INS.dir)

$(ROOTINTELDIR)/%: % $(ROOTINTELDIR)
	$(INS.file)

$(ROOTAMDDIR)/%: % $(ROOTAMDDIR)
	$(INS.file)

$(ROOTAMDFBDIR)/%: % $(ROOTAMDFBDIR)
	$(INS.file)
