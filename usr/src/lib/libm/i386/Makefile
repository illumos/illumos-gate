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
include ../Makefile.com

#
# Without this option GCC will place floats into x87 (or wider) floating point
# registers, ending up with better-than-ieee precision.
#
CFLAGS		+= -_gcc=-ffloat-store
$(OBJS_M9XSSE)	:= CFLAGS += -xarch=sse2

install: 	all $(ROOTLIBS) $(ROOTLINKS) $(ROOTLINT)

include ../Makefile.targ
