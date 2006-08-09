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
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../../Makefile.lib

PLATFORM=	sun4u-us3
ALT_PLAT=	sun4u_hwcap2

SUBDIRS=	$(MACH)
SUBDIRS64=	$(MACH64)

all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber

.KEEP_STATE:

all install clean clobber : lib32 \
				$(BUILD64) lib64

lint:
	@ $(ECHO) "Nothing to lint here: skipping"

lib32: $(SUBDIRS)

lib64: $(SUBDIRS64)

$(SUBDIRS) $(SUBDIRS64): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
