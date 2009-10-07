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
# Platform specific Makefile for libc_psr.
#

CLASS		= 32
PLATFORM	= sun4u

OBJECTS		= memcpy.o memset.o memcmp.o

include ../Makefile.com

ASFLAGS	+=	-xarch=v8plusa -warn

# Redefine shared object build rule to use $(LD) directly (this avoids .init
# and .fini sections being added).
 
BUILD.SO=	$(LD) -o $@ -G $(DYNFLAGS) $(PICS) $(LDLIBS)

.KEEP_STATE:

MODULE		= libc_psr.so.1
LIBC_PSR_DIRS	= $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib)
LIBC_PSR_LINKS	= $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MODULE))
INS.slink6	= $(RM) -r $@; $(SYMLINK) ../../$(PLATFORM)/lib/$(MODULE) $@

$(LIBC_PSR_DIRS):
	-$(INS.dir)

$(LIBC_PSR_LINKS): $(LIBC_PSR_DIRS)
	-$(INS.slink6)

all:		$(LIBS)

install:	all $(LIBC_PSR_LINKS) $(ROOT_PSM_LIBS)

include ../../Makefile.targ
