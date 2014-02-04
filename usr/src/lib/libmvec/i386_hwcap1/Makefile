#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
#

TARGET_ARCH=	i386

LIBRARY		= libmvec_hwcap1.a
VERS		= .1

OBJECTS=	$(mvecOBJS)

include ../Makefile.com

CPPFLAGS	+= -D_CMOV_INSN -D_SSE_INSN -D_SSE2_INSN
MAPFILES	+= mapfile
CFLAGS		+= -xtarget=pentium_pro -xarch=sse2

ROOTLIBDIR 	= $(ROOTFS_LIBDIR)/libmvec

install: 	all $(ROOTLIBDIR) $(ROOTLIBS)

include $(SRC)/lib/libm/Makefile.targ
