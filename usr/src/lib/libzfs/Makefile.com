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
# Copyright 2016 Igor Kozhukhov <ikozhukhov@gmail.com>
# Copyright (c) 2011, 2017 by Delphix. All rights reserved.
#

LIBRARY= libzfs.a
VERS= .1

OBJS_SHARED=			\
	zfeature_common.o	\
	zfs_comutil.o		\
	zfs_deleg.o		\
	zfs_fletcher.o		\
	zfs_namecheck.o		\
	zfs_prop.o		\
	zpool_prop.o		\
	zprop_common.o

OBJS_COMMON=			\
	libzfs_changelist.o	\
	libzfs_config.o		\
	libzfs_dataset.o	\
	libzfs_diff.o		\
	libzfs_fru.o		\
	libzfs_import.o		\
	libzfs_iter.o		\
	libzfs_mount.o		\
	libzfs_pool.o		\
	libzfs_sendrecv.o	\
	libzfs_status.o		\
	libzfs_util.o		\
	libzfs_taskq.o

OBJECTS= $(OBJS_COMMON) $(OBJS_SHARED)

include ../../Makefile.lib

# libzfs must be installed in the root filesystem for mount(1M)
include ../../Makefile.rootfs

LIBS=	$(DYNLIB) $(LINTLIB)

SRCDIR =	../common

INCS += -I$(SRCDIR)
INCS += -I../../../uts/common/fs/zfs
INCS += -I../../../common/zfs
INCS += -I../../libc/inc

CSTD=	$(CSTD_GNU99)
C99LMODE=	-Xc99=%all
LDLIBS +=	-lc -lm -ldevid -lgen -lnvpair -luutil -lavl -lefi \
	-ladm -lidmap -ltsol -lmd -lumem -lzfs_core -lcmdutils
CPPFLAGS +=	$(INCS) -D_LARGEFILE64_SOURCE=1 -D_REENTRANT
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

# There's no lint library for zlib, so only include this when building
$(DYNLIB) := LDLIBS +=	-lz

LINTFLAGS +=	-erroff=E_STATIC_UNUSED
LINTFLAGS64 +=	-erroff=E_STATIC_UNUSED

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
