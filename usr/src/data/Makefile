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
# Copyright 2017 Nexenta Systems, Inc.
#

COMMON_SUBDIRS=	consfonts \
		hwdata \
		locale \
		terminfo \
		zoneinfo

i386_SUBDIRS=	ucode

SUBDIRS = $(COMMON_SUBDIRS) $($(MACH)_SUBDIRS)

MSGSUBDIRS= 	zoneinfo

all :=		TARGET=all
clean :=	TARGET=clean
clobber :=	TARGET=clobber
install :=	TARGET=install
_msg :=		TARGET=_msg

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

_msg:		$(MSGSUBDIRS)

$(SUBDIRS):	FRC
		cd $@; pwd; $(MAKE) $(TARGET)

FRC:
