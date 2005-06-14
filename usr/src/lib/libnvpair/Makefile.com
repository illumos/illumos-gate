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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libnvpair/Makefile.com
#

LIBRARY=	libnvpair.a
VERS=		.1

OBJECTS=	libnvpair.o \
		nvpair_alloc_system.o \
		nvpair_alloc_fixed.o \
		nvpair.o

include ../../Makefile.lib
include ../../Makefile.rootfs

SRCS=		../libnvpair.c \
		../nvpair_alloc_system.c \
		$(SRC)/common/nvpair/nvpair_alloc_fixed.c \
		$(SRC)/common/nvpair/nvpair.c

SRCDIR=		..
MAPDIR=		../spec/$(TRANSMACH)
SPECMAPFILE=	$(MAPDIR)/mapfile

#
# Libraries added to the next line must be present in miniroot
#
LDLIBS +=	-lc -lnsl
LIBS =		$(DYNLIB) $(LINTLIB)

# turn off ptr-cast warnings
LINTFLAGS64 +=	-erroff=E_BAD_PTR_CAST_ALIGN

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ

pics/%.o: $(SRC)/common/nvpair/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
