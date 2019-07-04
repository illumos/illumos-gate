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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =		libhttp-core.a
VERS =			.1
OBJECTS = http-addr.o http-support.o http.o

ROOTLIBDIR =	$(ROOT)/usr/lib/print

include ../../../Makefile.lib

SRCDIR =	../common

ROOTLIBDIR=	$(ROOT)/usr/lib/print
ROOTLIBDIR64=	$(ROOT)/usr/lib/print/$(MACH)

LIBS =			$(DYNLIB)


CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR)
CPPFLAGS +=	-I../../libpapi-common/common

# not linted
SMATCH=off

MAPFILES =	$(SRCDIR)/mapfile

LDLIBS +=	-lsocket -lnsl -lc

.KEEP_STATE:

all:	$(LIBS)


$(ROOTLIBDIR):
	$(INS.dir)

include ../../../Makefile.targ
