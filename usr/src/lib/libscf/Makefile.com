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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY =	libscf.a
VERS =		.1

OBJECTS = \
	error.o			\
	lowlevel.o		\
	midlevel.o		\
	scf_type.o

include ../../Makefile.lib
include ../../Makefile.rootfs

LIBS =		$(DYNLIB) $(LINTLIB)

$(NOT_NATIVE)NATIVE_BUILD = $(POUND_SIGN)
$(NATIVE_BUILD)VERS =
$(NATIVE_BUILD)LIBS = $(DYNLIB)

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)
LDLIBS +=	-luutil -lc

SRCDIR =	../common
MAPDIR =	../spec/$(TRANSMACH)
SPECMAPFILE =	$(MAPDIR)/mapfile

COMDIR =	../../../common/svc

CFLAGS +=	-v -Wp,-xc99=%all
CPPFLAGS +=	-I../inc -I../../common/inc -I$(COMDIR)

#
# For native builds, we compile and link against the native version
# of libuutil.
#
LIBUUTIL =	$(SRC)/lib/libuutil
MY_NATIVE_CPPFLAGS =\
		-DNATIVE_BUILD $(DTEXTDOM) \
		-I../inc -I$(COMDIR) -I$(LIBUUTIL)/common
MY_NATIVE_LDLIBS = -L$(LIBUUTIL)/native -R$(LIBUUTIL)/native -luutil -ldoor -lc

.KEEP_STATE:

all:

lint: lintcheck

include ../../Makefile.targ
