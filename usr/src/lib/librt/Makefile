#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 1997-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/librt/Makefile
#
LIBRARY =	librt.a
VERS =		.1

include ../Makefile.lib

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

# conditional assignments
all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
catalog :=	TARGET= catalog
package :=	TARGET= package

# include common library definitions

#HDRS = 
ROOTHDRDIR =	$(ROOT)/usr/include/sys
ROOTHDRS =	$(HDRS:%=$(ROOTHDRDIR)/%)

$(ROOTHDRS) :=	FILEMODE = 644

.KEEP_STATE:

all install clean clobber: spec .WAIT $(SUBDIRS)

lint: $(SUBDIRS)

spec $(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

install:	$(ROOTLIBS) $(ROOTLINKS)

$(ROOTHDRDIR)/% : %
		$(INS.file)

install_h: $(ROOTHDRS)

clean clobber:	FRC
		@cd $(MACH); pwd; $(MAKE) $@

links:
		-$(RM) $(MACH)
		$(SYMLINK) `mach` $(MACH)

FRC:
