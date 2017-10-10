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
# Copyright 2013 Pluribus Networks Inc.
#

include		../Makefile.lib

HDRS =		vmmapi.h

HDRDIR =	common

CHECKHDRS =

$(BUILD64)SUBDIRS += $(MACH64)

all:=		TARGET= all
install:=	TARGET= install
clean:=	TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint
_msg:=		TARGET= _msg

.KEEP_STATE:

all install clean clobber lint: $(SUBDIRS)

# install rule for install_h target

install_h: $(ROOTHDRS)

check: $(CHECKHDRS)

_msg: $(MSGSUBDIRS)

$(SUBDIRS): FRC
	cd $@; pwd; $(MAKE) CW_NO_SHADOW=true __GNUC= $(TARGET)

FRC:

include ../Makefile.targ
include ../../Makefile.msg.targ
