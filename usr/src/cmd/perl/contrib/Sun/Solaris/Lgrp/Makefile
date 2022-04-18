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
# Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
# Copyright 2016 RackTop Systems.
#

include $(SRC)/Makefile.master

SUBDIRS=
$(BUILDPERL32)SUBDIRS += $(MACH)
$(BUILDPERL64)SUBDIRS += $(MACH64)

all :=		TARGET = all
install :=	TARGET = install
clean :=	TARGET = clean
clobber :=	TARGET = clobber

all install clean clobber: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
