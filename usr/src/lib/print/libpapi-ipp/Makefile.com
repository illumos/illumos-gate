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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =		psm-ipp.a
VERS =			.1
OBJECTS = ipp-support.o job.o printer.o service.o
ROOTLIBDIR =	$(ROOT)/usr/lib/print

include ../../../Makefile.lib
include ../../../Makefile.rootfs

SRCDIR =	../common

ROOTLIBDIR=	$(ROOT)/usr/lib/print
ROOTLIBDIR64=	$(ROOT)/usr/lib/print/$(MACH)

EXTRALINKS=	$(ROOTLIBDIR)/psm-http.so
$(EXTRALINKS):	$(ROOTLINKS)
	$(RM) $@; $(SYMLINK) $(LIBLINKS) $@

LIBS =			$(DYNLIB)

$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR)
CPPFLAGS +=	-I../../libpapi-common/common
CPPFLAGS +=	-I../../libipp-core/common
CPPFLAGS +=	-I../../libhttp-core/common

CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized

# not linted
SMATCH=off

MAPFILES =	$(SRCDIR)/mapfile

LDLIBS +=	-L$(ROOTLIBDIR) -R/usr/lib/print -lhttp-core -lmd5
LDLIBS +=	-lipp-core -lc

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

$(ROOTLIBDIR):
	$(INS.dir)

include ../../../Makefile.targ
