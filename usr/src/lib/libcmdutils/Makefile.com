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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2013 RackTop Systems.
#

LIBRARY=	libcmdutils.a
VERS=		.1
CMD_OBJS=	avltree.o sysattrs.o writefile.o process_xattrs.o uid.o gid.o
COM_OBJS=	list.o
OBJECTS=	$(CMD_OBJS) $(COM_OBJS)

include ../../Makefile.lib
include ../../Makefile.rootfs

LIBS =		$(DYNLIB) $(LINTLIB)

LDLIBS +=	-lc -lavl -lnvpair

SRCDIR =	../common

COMDIR= $(SRC)/common/list
SRCS=	\
	$(CMD_OBJS:%.o=$(SRCDIR)/%.c)   \
	$(COM_OBJS:%.o=$(COMDIR)/%.c)

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

CFLAGS +=	$(CCVERBOSE)

# All commands using the common avltree interfaces must
# be largefile aware.
CPPFLAGS +=	-I.. -I../../common/inc -D_REENTRANT -D_FILE_OFFSET_BITS=64

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: $(COMDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
