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
# Use is subject to license terms.
# Copyright 2012 OmniTI Computer Consulting, Inc.  All rights reserved.
#

include ../Makefile.lib

SUBDIRS	=	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

# Library header.
HDRS =		wanbootutil.h
HDRDIR =	common

# Headers who get installed into $(ROOT)/usr/include/wanboot
LOCHDRS =	key_util.h \
		key_xdr.h \
		wbio.h
LOCSRCS =	$(LOCHDRS:%=$(HDRDIR)/%)

# Must define targets for thise headers being installed into
# a non-default location.
WBKUHDRDIR =	$(ROOT)/usr/include/wanboot
WBKUHDRS =	$(LOCHDRS:%=$(WBKUHDRDIR)/%)

# Must override CHECKHDRS so that it does not check the
# RPC generated header.
CHECKHDRS =	$(HDRDIR)/key_util.check

# Must rpcgen XDR source.
RPCFILES =	common/key_xdr.c common/key_xdr.h

POFILE =	libwanbootutil.po
MSGFILES =	common/key_util.c
XGETFLAGS =	-a -x libwanbootutil.xcl

all := 		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install	:=	TARGET = install
lint :=		TARGET = lint

.KEEP_STATE:
.PARALLEL:      $(ROOTHDRS)

all clean clobber install: $(RPCFILES) $(SUBDIRS)

lint:		$(SUBDIRS)

install_h:	$(ROOTHDRDIR) $(WBKUHDRDIR) .WAIT $(ROOTHDRS) $(WBKUHDRS)

check:		$(CHECKHDRS)

$(POFILE):	pofile_MSGFILES

_msg:		$(MSGDOMAINPOFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

# No rules for this in Makefile.lib.
$(WBKUHDRDIR)/%: $(HDRDIR)/%
	$(INS.file)
$(WBKUHDRDIR):
	$(INS.dir)

# No rules for this in Makefile.lib.
common/key_xdr.c:	common/key_xdr.x
		cd common; $(RPCGEN) -cC -o key_xdr.c key_xdr.x; cd ..

common/key_xdr.h:	common/key_xdr.x
		cd common; $(RPCGEN) -h -o key_xdr.h key_xdr.x; cd ..

CLOBBERFILES += common/key_xdr.c common/key_xdr.h

include $(SRC)/Makefile.msg.targ
include $(SRC)/lib/Makefile.targ

