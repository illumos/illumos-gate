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
# libpool/Makefile.com
#

LIBRARY =	libpool.a
VERS =		.1

OBJECTS = \
	pool.o \
	pool_internal.o \
	pool_xml.o \
	pool_kernel.o \
	pool_commit.o \
	pool_value.o \
	dict.o

include ../../Makefile.lib

# Adding -lxml2 to LDLIBS would cause lint to complain as there is no .ln file
# for libxml2, so add it to DYNFLAGS
DYNFLAGS +=	-lxml2

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc -lnvpair -lexacct -lc
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

SRCDIR =	../common
MAPDIR =	../spec/$(TRANSMACH)
SPECMAPFILE =	$(MAPDIR)/mapfile

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -D_FILE_OFFSET_BITS=64 -I/usr/include/libxml2


.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ
