#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/lib/Makefile.lib

HDRS =		netinet/vrrp.h libvrrpadm.h
HDRDIR =	common

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

POFILE =	libvrrpadm.po
MSGFILES =      common/libvrrpadm.c

XGETFLAGS =	-a -x libvrrpadm.xcl

all :=		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install :=	TARGET = install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

install_h:	$(ROOTHDRS)

$(POFILE):	pofile_MSGFILES

_msg:		$(MSGDOMAINPOFILE)

check:		$(CHECKHDRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ
include $(SRC)/lib/Makefile.targ
