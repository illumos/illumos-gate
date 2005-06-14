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
# Copyright 1994, 2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/Makefile.master

# All the real work gets done in kernel-architecture directories,
# and that's where the targets wind up. This makefile just gets us there.

sparcv9_ARCHITECTURES = sparcv9
sparc_ARCHITECTURES = $(sparcv9_ARCHITECTURES)
SUBDIRS = $($(MACH)_ARCHITECTURES)

all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint
clean.lint	:=	TARGET= clean.lint

.KEEP_STATE:

all install clean clobber lint clean.lint: $(SUBDIRS)

TOPDIR= ../../..

#
# Cross-reference customization: include other relevant CPR-related code
# in the cross-reference.
#
STANDDIR =	$(TOPDIR)/stand
XRDIRS	+=	$(STANDDIR)/lib $(STANDDIR)/sys ../../promif \
		$(TOPDIR)/uts/*/cpr $(TOPDIR)/uts/*/sys/cpr_*

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
