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

LIBRARY 	= libmvec_isa.a
VERS 		= .1

TARGET_ARCH=	sparcv9
OBJECTS		= $(mvecvisCOBJS) $(mvecvisSOBJS)

include ../Makefile.com
include	$(SRC)/lib/Makefile.lib.64

CHIP		= vis
XARCH		= sparcvis

SRCS		= $(mvicvisCOBJS:%.o=../common/%.c)

MAPFILES	= ../common/mapfilevis-vers
ROOTLIBDIR64 	= $(ROOTFS_LIBDIR)/cpu/sparcv9+vis/$(MACH64)

install: all $(ROOTLIBDIR64) $(ROOTLIBS64)

include $(SRC)/lib/libm/Makefile.targ
