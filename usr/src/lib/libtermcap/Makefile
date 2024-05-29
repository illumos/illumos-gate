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
# Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
#

include		../Makefile.lib

HDRS =		termcap.h
HDRDIR=		common
SUBDIRS=	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

# Install XPG4v2 header variants so that libtermcap can be used to
# filter over libcurses(3xcurses).
XHDRS =		termcap.h
XROOTHDRDIR=	$(ROOT)/usr/xpg4/include
XROOTHDRS=	$(XHDRS:%=$(XROOTHDRDIR)/%)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

install_h: $(ROOTHDRS) $(XROOTHDRS)

check: $(CHECKHDRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(XROOTHDRDIR)/%: $(HDRDIR)/x%
	$(INS.rename)

FRC:

include ../Makefile.targ
