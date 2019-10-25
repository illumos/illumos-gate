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
<<<<<<< HEAD
# Copyright (c) 2018, Joyent, Inc.
=======
# Copyright 2019 Joyent, Inc.
>>>>>>> 7284664a1faa361af4ff33ba5435d43d3ee07bf2
#

include	$(SRC)/data/Makefile.data

ROOTUCODEPATH = $(ROOT)/platform/i86pc/ucode
ROOTAMDDIR = $(ROOTUCODEPATH)/AuthenticAMD
ROOTINTELDIR = $(ROOTUCODEPATH)/GenuineIntel

AMD_FILES :sh= (cd amd; print *)
INTEL_FILES :sh= (cd intel; print *)
<<<<<<< HEAD

ROOTAMDFILES = $(AMD_FILES:%=$(ROOTAMDDIR)/%)
ROOTINTELFILES = $(INTEL_FILES:%=$(ROOTINTELDIR)/%)
=======
include $(SRC)/data/ucode/Makefile.links

ROOTAMDFILES = $(AMD_FILES:%=$(ROOTAMDDIR)/%)
ROOTINTELFILES = $(INTEL_FILES:%=$(ROOTINTELDIR)/%)
ROOTINTELLINKS = $(INTEL_LINKS:%=$(ROOTINTELDIR)/%)
>>>>>>> 7284664a1faa361af4ff33ba5435d43d3ee07bf2

$(ROOTAMDFILES) := FILEMODE = 444
$(ROOTINTELFILES) := FILEMODE = 444

all:

<<<<<<< HEAD
install: $(ROOTAMDFILES) $(ROOTINTELFILES)
=======
install: $(ROOTAMDFILES) $(ROOTINTELFILES) $(ROOTINTELLINKS)
>>>>>>> 7284664a1faa361af4ff33ba5435d43d3ee07bf2

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
