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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/librsc/sparc/mpxu/Makefile

UTSBASE   = ../../../../uts

PLATFORM_OBJECTS= librsc.o

#
# platform library directory (/usr/platform/SUNW,Sun-Fire-V240/lib)
#
PLATFORM=SUNW,Sun-Fire-V240
LINKED_PLATFORMS = SUNW,Sun-Fire-V250
LINKED_PLATFORMS += SUNW,Sun-Fire-V440
LINKED_PLATFORMS += SUNW,Sun-Fire-V445
LINKED_PLATFORMS += SUNW,Sun-Fire-V215

include ../Makefile.com

$(USR_PSM_LIB_DIR):
	cd $(UTSBASE)/sun4u/mpxu; pwd; $(MAKE) $(USR_PSM_LIB_DIR)
