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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY		= libc_psr_hwcap2.a
VERS		= .1

include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

#
# Since libc_psr is strictly assembly, deactivate the CTF build logic.
#
CTFCONVERT_POST	= :
CTFMERGE_LIB	= :

LIBS		= $(DYNLIB)
IFLAGS		= -I$(SRC)/uts/sun4v \
		  -I$(ROOT)/usr/platform/sun4v/include -I$(ROOT)/usr/include/v9
CPPFLAGS	= -D_REENTRANT -D$(MACH) -DNIAGARA2_IMPL $(IFLAGS) $(CPPFLAGS.master)
ASDEFS		= -D__STDC__ -D_ASM $(CPPFLAGS)
ASFLAGS		= -P $(ASDEFS)

MAPFILES	= ../../sun4v/mapfile-vers ../mapfile $(MAPFILE.FLT)

#
# build rules
#
pics/%.o: ../../$(PLATFORM)/common/%.s
	$(AS) $(ASFLAGS) $< -o $@
	$(POST_PROCESS_O)
