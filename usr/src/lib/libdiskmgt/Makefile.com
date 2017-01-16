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
# Copyright 2016 Nexenta Systems, Inc.
#

LIBRARY =	libdiskmgt.a
VERS =		.1
OBJECTS =	alias.o \
		assoc_types.o \
		bus.o \
		cache.o \
		controller.o \
		drive.o \
		entry.o \
		events.o \
		findevs.o \
		inuse_dump.o \
		inuse_fs.o \
		inuse_lu.o \
		inuse_mnt.o \
		inuse_vxvm.o \
		inuse_zpool.o \
		media.o \
		partition.o \
		path.o \
		slice.o

include ../../Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)
i386_LDLIBS =   -lfdisk
sparc_LDLIBS =
LDLIBS +=       -ldevinfo -ladm -ldevid -lkstat -lsysevent \
		-lnvpair -lefi -lc $($(MACH)_LDLIBS)
DYNFLAGS +=	-R/opt/VRTSvxvm/lib

SRCDIR =	../common
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CPPFLAGS +=	-D_REENTRANT -I$(SRC)/lib/libdiskmgt/common

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ
