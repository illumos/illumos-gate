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

#
# Platform specific Makefile for libc_psr_hwcap2.
#

PLATFORM	= sun4u-us3
ALT_PLAT	= sun4u_hwcap2
COMPAT_PLAT	= sun4u
CLASS		= 32

OBJECTS		= memcpy.o memset.o memcmp.o

include ../Makefile.com

ASFLAGS	+=	-xarch=v8plusb

# Redefine shared object build rule to use $(LD) directly (this avoids .init
# and .fini sections being added).

BUILD.SO=	$(LD) -o $@ -G $(DYNFLAGS) $(PICS) $(LDLIBS)

.KEEP_STATE:

MODULE		= libc_psr_hwcap2.so.1
LIBC_PSR_DIR	= $(ROOT_PSM_LIB_DIR)/libc_psr
LIBC_PSR_LIB	= $(LIBC_PSR_DIR)/$(MODULE)
INS.libc	= $(RM) -r $@; $(INS) -s -f $(@D) $(MODULE)

$(LIBC_PSR_DIR):
	-$(INS.dir)

$(LIBC_PSR_LIB): $(LIBC_PSR_DIR) $(MODULE)
	-$(INS.libc)

all:		$(LIBS)

install:	all $(LIBC_PSR_LIB)

include ../../Makefile.targ
