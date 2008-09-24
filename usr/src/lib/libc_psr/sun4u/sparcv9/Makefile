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
#
# Platform specific Makefile for libc_psr.
#

PLATFORM	= sun4u
CLASS		= 64

OBJECTS		= memcpy.o memset.o memcmp.o

include ../Makefile.com

ASDEFS +=	-D__sparcv9
ASFLAGS	+=	-xarch=v9a

include $(SRC)/Makefile.master.64

# Redefine shared object build rule to use $(LD) directly (this avoids .init
# and .fini sections being added).
 
BUILD.SO=	$(LD) -o $@ -G $(DYNFLAGS) $(PICS) $(LDLIBS)

.KEEP_STATE:

MODULE		= libc_psr.so.1
LIBC_PSR64_DIRS = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MACH64))
LIBC_PSR64_LINKS = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MACH64)/$(MODULE))
INS.slink6	= $(RM) -r $@; $(SYMLINK) ../../../$(PLATFORM)/lib/$(MACH64)/$(MODULE) $@ $(CHOWNLINK) $(CHGRPLINK)

$(LIBC_PSR64_DIRS):
	-$(INS.dir.root.bin)

$(LIBC_PSR64_LINKS): $(LIBC_PSR64_DIRS)
	-$(INS.slink6)

all:		$(LIBS)

install:	all $(LIBC_PSR64_LINKS) $(ROOT_PSM_LIB64_DIR)/$(LIBS)

include ../../Makefile.targ
