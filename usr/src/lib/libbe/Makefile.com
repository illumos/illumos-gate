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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright 2012 OmniTI Computer Consulting, Inc.  All rights reserved.
# Copyright 2015 Nexenta Systems, Inc. All rights reserved.
# Copyright 2016 Toomas Soome <tsoome@me.com>
#


LIBRARY=	libbe.a
VERS=		.1

OBJECTS=	\
		be_activate.o \
		be_create.o \
		be_list.o \
		be_mount.o \
		be_rename.o \
		be_snapshot.o \
		be_utils.o \
		be_zones.o

include ../../Makefile.lib

LIBS=		$(DYNLIB) $(LINTLIB)

SRCDIR=		../common

INCS += -I$(SRCDIR) -I$(SRC)/cmd/boot/common -I$(SRC)/common/ficl

C99MODE=	$(C99_ENABLE)

LDLIBS +=	-lficl-sys -lzfs -linstzones -luuid -lnvpair -lc -lgen
LDLIBS +=	-ldevinfo -lefi
CPPFLAGS +=	$(INCS)
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-address

CLOBBERFILES += $(LIBRARY)

$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all: $(LIBS) $(LIBRARY)

lint: lintcheck

include ../../Makefile.targ
