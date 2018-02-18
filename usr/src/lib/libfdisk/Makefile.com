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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

LIBRARY= libfdisk.a
VERS= .1

OBJECTS=	libfdisk.o

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

SRCDIR=	../common

LIBS=	$(DYNLIB) $(LINTLIB)

CSTD=	$(CSTD_GNU89)

CPPFLAGS += -I.
LDLIBS += -lc

CFLAGS += -D_LARGEFILE64_SOURCE
CFLAGS += -D_FILE_OFFSET_BITS=64
CFLAGS64 += -D_LARGEFILE64_SOURCE
CFLAGS64 += -D_FILE_OFFSET_BITS=64

LINTFLAGS +=    -erroff=E_BAD_PTR_CAST_ALIGN
LINTFLAGS64 +=    -erroff=E_BAD_PTR_CAST_ALIGN

CERRWARN +=	-_gcc=-Wno-uninitialized

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

# include library targets
include ../../Makefile.targ
