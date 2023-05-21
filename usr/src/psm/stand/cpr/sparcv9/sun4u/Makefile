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
# Copyright 1995-1999,2002-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

TOPDIR =	../../../../..

# override global macros as necessary
TARGET_ARCH =	sun4u
TARG_MACH =     sparcv9
ARCH =		sun4u
MACH =		sparc
MMU =		sfmmu
ARCHVER =	v9
PROMTYPE =	ieee1275
ARCH_PROMDIR =	$(TARG_MACH)/$(PROMTYPE)/common
PROMIFDIR =	$(TOPDIR)/psm/stand/lib/promif
PLATLIBDIR =	$(PROMIFDIR)/$(TARG_MACH)/$(PROMTYPE)/$(TARGET_ARCH)
PLATLIB =	$(PLATLIBDIR)/libplat.a
LDLIBS =	-L$(PLATLIBDIR) -lplat
SALIBS =	$(PLATLIB)
LINTLIBS =	$(PLATLIBDIR)/llib-lplat.ln

CPRBOOTOBJ = cb_srt0.o cprboot.o machdep.o pages.o bitmap.o util.o

ALL = cprboot

include ../../common/Makefile.com
include $(TOPDIR)/psm/Makefile.psm.64
CFLAGS64 += -xchip=ultra
CERRWARN += $(CNOWARN_UNINIT)

.KEEP_STATE:

STANDDIR =	$(TOPDIR)/stand
CPPINCS	+=	-I$(STANDDIR)

#
# Cross-reference customization: build a cross-reference over all of
# the sun4u-related CPR source files.
#
XRDIRS	+=	../../common \
		$(STANDDIR)/lib $(STANDDIR)/sys \
		../../../../promif/ieee1275 \
		$(TOPDIR)/uts/common/os/compress.c \
		$(TOPDIR)/uts/common/sys/cpr.h \
		$(TOPDIR)/uts/sun4u/sys/cpr_impl.h
