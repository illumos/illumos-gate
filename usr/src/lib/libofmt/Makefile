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

include		$(SRC)/lib/Makefile.lib

SUBDIRS=	$(MACH) $(BUILD64) $(MACH64)

HDRS=		ofmt.h
HDRDIR=		common

POFILE=		libofmt.po
MSGFILES=	common/ofmt.c
XGETFLAGS=	-a

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

install_h:	$(ROOTHDRS)

check:		$(CHECKHDRS)

$(POFILE):	$(MSGFILES)
		$(BUILDPO.msgfiles)

_msg:		$(MSGDOMAINPOFILE)

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include		$(SRC)/Makefile.msg.targ
include		$(SRC)/lib/Makefile.targ
