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
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

UTSBASE	  = ../../..

#
# include global definitions
#
include ../Makefile.sunfire

#
# Override defaults.
#
FILEMODE	 = 644
GROUP = bin

HDRS=			ac.h environ.h fhc.h simmstat.h sysctrl.h
CLOSEDHDRS=		sram.h

ROOTHDRS=		$(HDRS:%=$(USR_SUNFIRE_ISYS_DIR)/%)
$(CLOSED_BUILD)ROOTHDRS += $(CLOSEDHDRS:%=$(USR_SUNFIRE_ISYS_DIR)/%)

ROOTDIR=		$(ROOT)/usr/share/src
ROOTDIRS=		$(ROOTDIR)/uts $(ROOTDIR)/uts/$(PLATFORM)

ROOTLINK=		$(ROOTDIR)/uts/$(PLATFORM)/sys
LINKDEST=		../../../../platform/$(PLATFORM)/include/sys

CHECKHDRS=		$(HDRS:%.h=%.check)
$(CLOSED_BUILD)CHECKHDRS += \
	$(CLOSEDHDRS:%.h=$(CLOSED)/uts/sun4u/sunfire/sys/%.check)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS) $(ROOTHDRS)

install_h: $(ROOTDIRS) .WAIT $(ROOTHDRS) $(ROOTLINK)

check:	$(CHECKHDRS)

#
# install rules
#
$(USR_SUNFIRE_ISYS_DIR)/%:	% $(USR_SUNFIRE_ISYS_DIR)
	$(INS.file)

$(USR_SUNFIRE_ISYS_DIR)/%:	$(CLOSED)/uts/sun4u/sunfire/sys/%
	$(INS.file)

$(ROOTDIRS):
	$(INS.dir.root.bin)

# -r because this used to be a directory and is now a link.
$(ROOTLINK):	$(ROOTDIRS)
	-$(RM) -r $@; $(SYMLINK) $(LINKDEST) $@ $(CHOWNLINK) $(CHGRPLINK)

FRC:

include ../Makefile.targ
