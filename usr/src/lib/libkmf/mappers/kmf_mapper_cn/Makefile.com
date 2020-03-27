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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#
# KMF CN mapper. Maps a certificate to its Common Name value.
#

LIBRARY =	kmf_mapper_cn.a
VERS =		.1

OBJECTS =	mapper_cn.o

include	$(SRC)/lib/Makefile.lib

LIBLINKS =	$(DYNLIB:.so.1=.so)
KMFINC =	-I../../../include

SRCDIR =	../common
INCDIR =	../../include

SRCS =		$(OBJECTS:%.o=$(SRCDIR)/%.c)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I../../../include -I$(INCDIR)

PICS =		$(OBJECTS:%=pics/%)

LDLIBS +=	-lkmf -lc

ROOTLIBDIR =	$(ROOTFS_LIBDIR)/crypto
ROOTLIBDIR64 =	$(ROOTFS_LIBDIR)/crypto/$(MACH64)

.KEEP_STATE:

LIBS =		$(DYNLIB)

all:		$(LIBS)


FRC:

include $(SRC)/lib/Makefile.targ
