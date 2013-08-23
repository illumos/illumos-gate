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
# Copyright (c) 2013 by Delphix. All rights reserved.
#

LIBRARY= libzpool.a
VERS= .1

# include the list of ZFS sources
include ../../../uts/common/Makefile.files
KERNEL_OBJS = kernel.o taskq.o util.o
DTRACE_OBJS = zfs.o

OBJECTS=$(ZFS_COMMON_OBJS) $(ZFS_SHARED_OBJS) $(KERNEL_OBJS)

# include library definitions
include ../../Makefile.lib

ZFS_COMMON_SRCS=	$(ZFS_COMMON_OBJS:%.o=../../../uts/common/fs/zfs/%.c)
ZFS_SHARED_SRCS=	$(ZFS_SHARED_OBJS:%.o=../../../common/zfs/%.c)
KERNEL_SRCS=		$(KERNEL_OBJS:%.o=../common/%.c)

SRCS=$(ZFS_COMMON_SRCS) $(ZFS_SHARED_SRCS) $(KERNEL_SRCS)
SRCDIR=		../common

# There should be a mapfile here
MAPFILES =

LIBS +=		$(LINTLIB)

INCS += -I../common
INCS += -I../../../uts/common/fs/zfs
INCS += -I../../../common/zfs
INCS += -I../../../common

CLEANFILES += ../common/zfs.h
CLEANFILES += $(EXTPICS)

$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)
$(LINTLIB): ../common/zfs.h

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

CFLAGS +=	-g $(CCVERBOSE) $(CNOGLOBAL)
CFLAGS64 +=	-g $(CCVERBOSE)	$(CNOGLOBAL)
LDLIBS +=	-lcmdutils -lumem -lavl -lnvpair -lz -lc -lsysevent -lmd
CPPFLAGS +=	$(INCS)	-DDEBUG

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-empty-body
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-unused-label

.KEEP_STATE:

all: $(LIBS)

lint: $(LINTLIB)

include ../../Makefile.targ

EXTPICS= $(DTRACE_OBJS:%=pics/%)

pics/%.o: ../../../uts/common/fs/zfs/%.c ../common/zfs.h
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../../../common/zfs/%.c ../common/zfs.h
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/%.d $(PICS)
	$(COMPILE.d) -C -s $< -o $@ $(PICS)
	$(POST_PROCESS_O)

../common/%.h: ../common/%.d
	$(DTRACE) -xnolibs -h -s $< -o $@
