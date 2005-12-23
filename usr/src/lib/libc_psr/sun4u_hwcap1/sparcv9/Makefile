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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Platform specific Makefile for libc_psr_hwcap1.
#
PLATFORM	= sun4u-us3
ALT_PLAT	= sun4u_hwcap1
COMPAT_PLAT	= sun4u
CLASS		= 64

OBJECTS		= memcpy.o memset.o memcmp.o

include ../Makefile.com

MAPDIR=		../../spec/$(ALT_PLAT)/$(MACH64)
MAPFILE=	$(MAPDIR)/mapfile-$(MACH64)

MAPFILES=	$(MAPFILE) $(MAPFILE-FLTR)
MAPOPTS=	$(MAPFILES:%=-M %)
DYNFLAGS +=	$(MAPOPTS)
CLOBBERFILES +=	$(MAPFILE)

ASDEFS +=	-D__sparcv9
ASFLAGS	+=	-xarch=v9b

include $(SRC)/Makefile.master.64

# Redefine shared object build rule to use $(LD) directly (this avoids .init
# and .fini sections being added).

BUILD.SO=	$(LD) -o $@ -G $(DYNFLAGS) $(PICS) $(LDLIBS)

$(DYNLIB):	$(MAPFILES)

$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) `basename $@`

.KEEP_STATE:

MODULE		= libc_psr_hwcap1.so.1
LIBC_PSR64_DIR	= $(ROOT_PSM_LIB_DIR)/$(MACH64)/libc_psr
LIBC_PSR64_LIB	= $(LIBC_PSR64_DIR)/$(MODULE)
INS.libc.64	= $(RM) -r $@; $(INS) -s -f $(@D) $(MODULE)

$(LIBC_PSR64_DIR):
	-$(INS.dir.root.bin)

$(LIBC_PSR64_LIB): $(LIBC_PSR64_DIR) $(MODULE)
	-$(INS.libc.64)

all:		$(LIBS)

install:	all $(LIBC_PSR64_LIB)

include ../../Makefile.targ
