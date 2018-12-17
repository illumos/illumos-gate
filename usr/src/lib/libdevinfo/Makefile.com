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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY=	libdevinfo.a
VERS=		.1

OBJECTS=	devfsinfo.o devinfo.o devinfo_prop_decode.o devinfo_devlink.o \
		devinfo_devperm.o devfsmap.o devinfo_profile.o \
		devinfo_finddev.o devinfo_dli.o devinfo_dim.o \
		devinfo_realpath.o devinfo_retire.o

include ../../Makefile.lib
include ../../Makefile.rootfs

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lnvpair -lsec -lc -lgen
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I..
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

# not linted
SMATCH=off

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ
