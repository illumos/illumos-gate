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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# uts/i86pc/sys/Makefile
#
UTSBASE = ../..

#
# include global definitions
#
include ../Makefile.i86pc

#
# Override defaults.
#
FILEMODE = 644
OWNER = root
GROUP = bin

HDRS=  \
	asm_misc.h	\
	clock.h		\
	cram.h		\
	ddi_subrdefs.h	\
	debug_info.h 	\
	mach_mmu.h	\
	machclock.h	\
	machcpuvar.h	\
	machparam.h	\
	machprivregs.h	\
	machsystm.h	\
	machthread.h	\
	memnode.h	\
	pc_mmu.h	\
	psm.h		\
	psm_defs.h	\
	psm_modctl.h	\
	psm_types.h	\
	rm_platter.h	\
	smp_impldefs.h	\
	vm_machparam.h	\
	x_call.h	\
	xc_levels.h	\
	xsvc.h

ROOTHDRS=	$(HDRS:%=$(USR_PSM_ISYS_DIR)/%)

ROOTDIR=	$(ROOT)/usr/share/src
ROOTDIRS=	$(ROOTDIR)/uts $(ROOTDIR)/uts/$(PLATFORM)

ROOTLINK=	$(ROOTDIR)/uts/$(PLATFORM)/sys
LINKDEST=	../../../../platform/$(PLATFORM)/include/sys

CHECKHDRS=	$(HDRS:%.h=%.check)

.KEEP_STATE:

.PARALLEL:	$(CHECKHDRS) $(ROOTHDRS)

install_h:	$(ROOTDIRS) .WAIT $(ROOTHDRS) $(ROOTLINK)

check:		$(CHECKHDRS)

$(ROOTDIRS):
	$(INS.dir.root.bin)

$(ROOTLINK):	$(ROOTDIRS)
	-$(RM) -r $@; $(SYMLINK) $(LINKDEST) $@ $(CHOWNLINK) $(CHGRPLINK)

FRC:

include ../../Makefile.targ
