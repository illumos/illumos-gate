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
# Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Platform specific Makefile for libmd5_psr.
#
# PLATFORM is the target for the binary installation.
#
PLATFORM = sun4u

MAPDIR = ../../spec/$(MACH)/$(PLATFORM)

include ../../Makefile.com

#
# Defining sun4u turns on sun4u-specific optimization
#
CPPFLAGS += -Dsun4u
CFLAGS += -xarch=v8plusa

.KEEP_STATE:

#
# Used when building links in /platform/$(PLATFORM)/lib for libmd5_psr.so.1
#
MODULE	= libmd5_psr.so.1

LIBMD5_PSR_DIRS = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib)
LIBMD5_PSR_LINKS = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MODULE))
INS.slink6 = $(RM) -r $@; $(SYMLINK) ../../$(PLATFORM)/lib/$(MODULE) $@ $(CHOWNLINK) $(CHGRPLINK)

$(LIBMD5_PSR_DIRS):
	-$(INS.dir.root.bin)

$(LIBMD5_PSR_LINKS): $(LIBMD5_PSR_DIRS)
	-$(INS.slink6)

all:		$(LIBS)

install:	all $(LIBMD5_PSR_LINKS) $(ROOT_PSM_LIBS)

include	../../Makefile.targ
