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
# Copyright (c) 2000-2001 by Sun Microsystems, Inc.
# All rights reserved.
#

include	$(SRC)/lib/Makefile.lib

SUBDIRS = .WAIT $(MACH)

all :=		TARGET= all
install :=      TARGET= install
clean :=        TARGET= clean
clobber :=      TARGET= clobber
_msg :=         TARGET= _msg

sparc_HDRS=
sparcv9_HDRS=
i386_HDRS=
HDRS=	$($(MACH)_HDRS)
ROOTHDRDIR=     $(ROOT)/usr/include
ROOTHDRS=       $(HDRS:%=$(ROOTHDRDIR)/%)
CHECKHDRS=      $(HDRS:%.h=%.check)

.KEEP_STATE:

all install clean clobber: $(SUBDIRS)

_msg:	$(MACH) $(MACH64)


$(ROOTHDRDIR)/%: %
	$(INS.file)

$(ROOTHDRDIR):
	$(INS.dir)

check: $(CHECKHDRS)

$(MACH) $(MACH64): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

