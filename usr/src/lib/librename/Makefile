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
# Copyright (c) 2014 Joyent, Inc.  All rights reserved.
#

include		../Makefile.lib

HDRS =		librename.h
HDRDIR =	common
SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS +=	$(MACH64)

all :=		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install :=	TARGET = install
lint :=		TARGET = lint

.KEEP_STATE:

all clean clobber lint: $(SUBDIRS)

install: 	$(SUBDIRS) $(VARPD_MAPFILES) install_h

install_h: 	$(ROOTHDRS)

check:		$(CHECKHDRS)

$(SUBDIRS):  FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
