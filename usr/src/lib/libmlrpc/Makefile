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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include $(SRC)/lib/Makefile.lib

HDRS=		libmlrpc.h ndr.h ndrtypes.ndl rpcpdu.ndl
HDRDIR=		common

ROOTHDRDIR=	$(ROOT)/usr/include/libmlrpc
ROOTHDRS= $(HDRS:%=$(ROOTHDRDIR)/%)

# ISA targets
SUBDIRS = $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET = all
install :=	TARGET = install
clean :=	TARGET = clean
clobber :=	TARGET = clobber
lint :=		TARGET = lint

.KEEP_STATE:

all install clean clobber lint: $(SUBDIRS)

install_h: $(ROOTHDRDIR) $(ROOTHDRS)

check: $(CHECKHDRS)

$(ROOTHDRDIR)/%: %
	$(INS.file)

$(ROOTHDRDIR):
	$(INS.dir)

$(SUBDIRS): FRC
	@cd $@; pwd; VERSION='$(VERSION)' $(MAKE) $(TARGET)

FRC:

include $(SRC)/lib/Makefile.targ
