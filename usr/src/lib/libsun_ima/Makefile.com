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

LIBRARY =	libsun_ima.a
VERS =		.1
LOCOBJS =	ima.o
COMDIR =	$(SRC)/common/iscsi
COMOBJS =	utils.o
OBJECTS =	$(LOCOBJS) $(COMOBJS)

include ../../Makefile.lib

SRCS =          ../common/ima.c $(SRC)/common/iscsi/utils.c
$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

SRCDIR =	../common

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc
LDLIBS +=	-lnsl
LDLIBS +=	-ldevinfo
LDLIBS +=	-lsysevent

CFLAGS +=	-mt
CFLAGS +=	$(CCVERBOSE)
CFLAGS64 +=	-mt
CFLAGS64 +=	$(CCVERBOSE)

CERRWARN +=	-_gcc=-Wno-parentheses

# not linted
SMATCH=off

CPPFLAGS +=	-DSOLARIS

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

include ../../Makefile.targ

pics/utils.o:	$(SRC)/common/iscsi/utils.c
	$(COMPILE.c) -o $@ $(SRC)/common/iscsi/utils.c
	$(POST_PROCESS_O)
