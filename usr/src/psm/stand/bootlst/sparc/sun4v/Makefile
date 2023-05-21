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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

TOPDIR =	../../../../..
SPARCDIR =	..

# override global macros as necessary
ARCH =		sun4v
TARG_MACH =	sparcv9
PROMTYPE =	ieee1275
PROMIFDIR =	$(TOPDIR)/psm/stand/lib/promif
PLATDIR =	$(TOPDIR)/uts/$(ARCH)

ARCH_PROMDIR =	$(TARG_MACH)/$(PROMTYPE)/common
PLAT_PROMDIR =	$(PROMTYPE)/$(ARCH)
PLATLIBDIR =	$(PROMIFDIR)/$(TARG_MACH)/$(PLAT_PROMDIR)
PLATLIB =	$(PLATLIBDIR)/libplat.a

LDPLATLIBS =	-L$(PLATLIBDIR) -lplat
SALIBS =	$(PLATLIB)
MAPFILE =	$(SPARCDIR)/mapfile
LINTPLATLIBS =	$(PLATLIBDIR)/llib-lplat.ln

BOOTLSTOBJ = srt0.o

ALL = bootlst

%.o: $(SPARCDIR)/%.s
	$(COMPILE.s) -o $@ $<

%.ln: $(SPARCDIR)/%.s
	@$(LHEAD) $(LINT.s) $< $(LTAIL)


include ../../common/Makefile.com
include $(TOPDIR)/psm/Makefile.psm.64
CFLAGS64 += -xchip=ultra
CERRWARN += -_gcc=-Wno-char-subscripts
.KEEP_STATE:

