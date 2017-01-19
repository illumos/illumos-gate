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
# Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
#

LIBRARY= libzfs_core.a
VERS= .1

OBJS_SHARED=

OBJS_COMMON=			\
	libzfs_core.o

OBJECTS= $(OBJS_COMMON) $(OBJS_SHARED)

include ../../Makefile.lib

# libzfs_core must be installed in the root filesystem for mount(1M)
include ../../Makefile.rootfs

LIBS=	$(DYNLIB) $(LINTLIB)

SRCDIR =	../common

INCS += -I$(SRCDIR)
INCS += -I../../../uts/common/fs/zfs
INCS += -I../../../common/zfs
INCS += -I../../libc/inc

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all
LDLIBS +=	-lc -lnvpair
CPPFLAGS +=	$(INCS) -D_LARGEFILE64_SOURCE=1 -D_REENTRANT
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

SRCS=	$(OBJS_COMMON:%.o=$(SRCDIR)/%.c)	\
	$(OBJS_SHARED:%.o=$(SRC)/common/zfs/%.c)
$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: ../../../common/zfs/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
