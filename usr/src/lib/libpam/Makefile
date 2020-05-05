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

include ../Makefile.lib

SUBDIRS=	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

TEXT_DOMAIN=	SUNW_OST_SYSOSPAM
POFILE=		libpam.po
MSGFILES=	pam_framework.c

HDRS=		pam_appl.h pam_modules.h pam_impl.h
ROOTHDRDIR=	$(ROOT)/usr/include/security
HDRDIR=		.

# install pam.conf
ETCFILES=	pam.conf
ROOTETC=	$(ROOT)/etc
IETCFILES=	$(ETCFILES:%=$(ROOTETC)/%)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

install_h:	$(ROOTHDRS)

install:	$(IETCFILES)

check:		$(CHECKHDRS)

$(POFILE):	$(MSGFILES)
	$(BUILDPO.msgfiles)

_msg:		$(MSGDOMAINPOFILE)

include		$(SRC)/Makefile.msg.targ

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTETC)/%:	%
	$(INS.file)
FRC:

include ../Makefile.targ
