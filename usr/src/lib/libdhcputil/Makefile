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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Copyright 2012 OmniTI Computer Consulting, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/lib/Makefile.lib

LOCHDRS =	dhcp_inittab.h dhcp_symbol.h dhcpmsg.h
COMHDRS =	dhcp_impl.h dhcp_symbol_common.h
HDRS =		$(LOCHDRS) $(COMHDRS)
LOCHDRDIR =	common
COMHDRDIR =	$(SRC)/common/net/dhcp
HDRDIR =	$(LOCHDRDIR)
SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)
POFILE =	libdhcputil.po
MSGFILES =	common/dhcpmsg.c
XGETFLAGS =	-a -x libdhcputil.xcl

# Override HDRSRCS so check only local headers
HDRSRCS =	$(LOCHDRS:%=$(HDRDIR)/%)

all :=		TARGET = all
clean :=	TARGET = clean
clobber	:=	TARGET = clobber
install	:=	TARGET = install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

install_h:	$(ROOTHDRS)

$(ROOTHDRDIR)/%: $(COMHDRDIR)/%
	$(INS.file)

check:		$(CHECKHDRS)

$(POFILE):	pofile_MSGFILES

_msg:		$(MSGDOMAINPOFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ
include $(SRC)/lib/Makefile.targ
