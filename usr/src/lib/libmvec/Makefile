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
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
#

LIBRARY=	libmvec.a
VERS=		.1

# include common library definitions
include $(SRC)/lib/Makefile.lib

COMPS_i386	= i386_hwcap1
COMPS_sparc	= sparc_sparcv8plus+vis sparc_sparcv9+vis2
COMPONENTS	= $(COMPS_$(MACH))

COMPS_amd64	=
COMPS_sparcv9	= sparcv9_sparcv9+vis sparcv9_sparcv9+vis2
COMPONENTS64	= $(COMPS_$(MACH64))

SUBDIRS 	= $(MACH) $(COMPONENTS)
$(BUILD64)SUBDIRS += $(MACH64) $(COMPONENTS64)

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint

.KEEP_STATE:

.PARALLEL: $(SUBDIRS)

all clean clobber install lint: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; VERSION='$(VERSION)' $(MAKE) $(TARGET)

FRC:

include $(SRC)/lib/Makefile.targ
