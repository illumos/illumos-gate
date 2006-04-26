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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY=	libaio.a
VERS=		.1

COBJS= 		aio.o	\
		posix_aio.o	\
		scalls.o	\
		sig.o	\
		subr.o	\
		ma.o

OBJECTS=	$(COBJS) $(MOBJS)

include ../../Makefile.lib
include ../../Makefile.rootfs

SRCS=		$(COBJS:%.o=../common/%.c)

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

SRCDIR =	../common
MAPDIR =	../spec/$(TRANSMACH)
SPECMAPFILE =	$(MAPDIR)/mapfile

# Setting LIBAIO_DEBUG = -DDEBUG (make LIBAIO_DEBUG=-DDEBUG ...)
# enables ASSERT() checking and other verification in the library.
# This is automatically enabled for DEBUG builds, not for non-debug builds.
LIBAIO_DEBUG =
$(NOT_RELEASE_BUILD)LIBAIO_DEBUG = -DDEBUG

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	$(LIBAIO_DEBUG) -D_REENTRANT -I.. -I$(SRCDIR) -I../../common/inc

DYNFLAGS +=	$(ZINTERPOSE)

.KEEP_STATE:

all: $(LIBS) fnamecheck

lint: lintcheck

include ../../Makefile.targ

pics/%.o: $(MDIR)/%.s
	$(BUILD.s)
	$(POST_PROCESS_O)
