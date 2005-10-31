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
#ident	"%Z%%M%	%I%	%E% SMI"

LIBRARY= libzfs_jni.a
VERS= .1

OBJS_COMMON=	libzfs_jni_dataset.o \
		libzfs_jni_disk.o \
		libzfs_jni_diskmgt.o \
		libzfs_jni_main.o \
		libzfs_jni_pool.o \
		libzfs_jni_property.o \
		libzfs_jni_util.o
OBJECTS= $(OBJS_COMMON)

include ../../Makefile.lib

LIBS=	$(DYNLIB) $(LINTLIB)

INCS += -I$(SRCDIR) \
	-I../../../common/zfsj \
	-I$(JAVA_ROOT)/include \
	-I$(JAVA_ROOT)/include/solaris

LDLIBS +=	-lc -lnvpair -ldiskmgt -lzfs
CPPFLAGS +=	$(INCS)

SRCS=	$(OBJS_COMMON:%.o=$(SRCDIR)/%.c)
$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

SRCDIR=		../common
MAPDIR=		../spec/$(TRANSMACH)
SPECMAPFILE=	$(MAPDIR)/mapfile

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: ../../../common/zfsj/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
