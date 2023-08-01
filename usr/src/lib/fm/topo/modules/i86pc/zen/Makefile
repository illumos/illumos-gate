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
# Copyright 2023 Oxide Computer Company
#

MODULE = zen
ARCH = i86pc
CLASS = arch

MODULESRCS = topo_zen.c topo_zen_tn.c
ZENDIR = ../../common/zen/

include ../../Makefile.plugin

CPPFLAGS += -I$(ZENDIR) -I$(SRC)/uts/intel/io/amdzen -I$(SRC)/uts/intel
LDLIBS += -lfmd_agent -lumem -lkstat

%.o: $(ZENDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)
