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
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
#

include $(SRC)/lib/Makefile.lib

HDRS=		dsgetdc.h
HDRDIR=		common

ROOTHDRDIR=	$(ROOT)/usr/include/ads
ROOTHDRS= $(HDRS:%=$(ROOTHDRDIR)/%)

# ISA targets
SUBDIRS	=	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

DERIVED_FILES=  \
	common/ads_priv.h \
	common/adspriv_xdr.c

RPCGENFLAGS = -CMN

CLEANFILES += $(DERIVED_FILES)

all := 		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install	:=	TARGET = install
lint :=		TARGET = lint

.KEEP_STATE:

all:	$(DERIVED_FILES) .WAIT $(SUBDIRS)

install: all .WAIT $(SUBDIRS)

install_h: $(DERIVED_FILES) $(ROOTHDRS)

clean clobber lint: $(SUBDIRS)

check:		$(CHECKHDRS)

common/ads_priv.h: $(HDRDIR)/ads_priv.x
	$(RPCGEN) $(RPCGENFLAGS) -h $(HDRDIR)/ads_priv.x > $@

common/adspriv_xdr.c: $(HDRDIR)/ads_priv.x
	$(RPCGEN) $(RPCGENFLAGS) -c $(HDRDIR)/ads_priv.x > $@

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ
include $(SRC)/lib/Makefile.targ
