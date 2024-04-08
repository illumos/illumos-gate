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
# Copyright 2020 Joyent, Inc.
# Copyright 2024 Oxide Computer Company
#

LIBRARY= libzfs.a
VERS= .1

amd64_OBJS_SHARED=		\
	zfs_fletcher_avx512.o	\
	zfs_fletcher_intel.o	\
	zfs_fletcher_sse.o

OBJS_SHARED=				\
	$($(MACH64)_OBJS_SHARED)	\
	zfeature_common.o		\
	zfs_comutil.o			\
	zfs_deleg.o			\
	zfs_fletcher.o			\
	zfs_fletcher_superscalar.o	\
	zfs_fletcher_superscalar4.o	\
	zfs_namecheck.o			\
	zfs_prop.o			\
	zpool_prop.o			\
	zprop_common.o

OBJS_COMMON=			\
	libzfs_changelist.o	\
	libzfs_config.o		\
	libzfs_crypto.o		\
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

# libzfs must be installed in the root filesystem for mount(8)
include ../../Makefile.rootfs

LIBS=	$(DYNLIB)

SRCDIR =	../common

INCS += -I$(SRCDIR)
INCS += -I../../../uts/common/fs/zfs
INCS += -I../../../common/zfs
INCS += -I../../libc/inc
INCS += -I../../libzutil/common

CSTD=	$(CSTD_GNU99)
LDLIBS +=	-lc -lm -ldevid -lgen -lnvpair -luutil -lavl -lefi \
	-lidmap -ltsol -lcryptoutil -lpkcs11 -lmd -lumem -lzfs_core \
	-ldevinfo -lzutil
CPPFLAGS +=	$(INCS) -D_LARGEFILE64_SOURCE=1 -D_REENTRANT
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

# not linted
SMATCH=off

LDLIBS +=	-lz
NATIVE_LIBS += libz.so

SRCS=	$(OBJS_COMMON:%.o=$(SRCDIR)/%.c)	\
	$(OBJS_SHARED:%.o=$(SRC)/common/zfs/%.c)

.KEEP_STATE:

all: $(LIBS)

pics/%.o: ../../../common/zfs/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
