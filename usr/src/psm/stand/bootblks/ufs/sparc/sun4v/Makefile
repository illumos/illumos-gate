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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# psm/stand/bootblks/ufs/sparc/sun4v/Makefile
#

#
# Platform specific Makefile for the boot block.
#
# PLATFORM is the target for the binary installation.
#
# PLATLINKS is a list of platforms which are to be linked to the ../fs
#	directory.
#
BASEDIR		= ../../..
PLATFORM	= sun4v

#PLATLINKS	= SUNW,...

#LINKED_DIRS             = $(PLATLINKS:%=$(USR_PLAT_DIR)/%)
#LINKED_LIB_DIRS         = $(PLATLINKS:%=$(USR_PLAT_DIR)/%/lib)
#LINKED_LIB_FS_DIRS	= $(PLATLINKS:%=$(USR_PLAT_DIR)/%/lib/fs)

include $(BASEDIR)/ufs/Makefile.ufs
include $(BASEDIR)/Makefile.1275

.KEEP_STATE:

all:	$(PROG)

include $(BASEDIR)/Makefile.targ
