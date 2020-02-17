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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2020 Joyent, Inc.
#

LIBRARY =	sn1_brand.a
VERS =		.1
COBJS =		sn1_brand.o
ASOBJS =	crt.o handler.o runexe.o brand_util.o
OBJECTS =	$(COBJS)

include ../../Makefile.sn1
include $(SRC)/lib/Makefile.lib

SRCDIR =	../common
UTSBASE =	$(SRC)/uts

LIBS =		$(DYNLIB)
CSRCS =		$(COBJS:%o=../common/%c)
SHAREDOBJS =	$(ASOBJS:%o=$(ISAOBJDIR)/%o)
SRCS =		$(CSRCS)

#
# Note that the architecture specific makefiles MUST update DYNFLAGS to
# explicily specify an interpreter for the brand emulation library.
# Normally this would be the native linker, /.SUNWnative/usr/lib/ld.so.1
# or /.SUNWnative/usr/lib/64/ld.so.1.
#
# Note that we make sure to link our brand emulation library
# libmapmalloc.  This is required because in most cases there will be two
# copies of libc in the same process and we don't want them to fight over
# the heap.  So for our brand library we link against libmapmalloc so that
# if we (our or copy of libc) try to allocate any memory it will be done
# via mmap() instead of brk().
#
# XXX: Note that we also set the runtime path for the emulation library to
# point into /.SUNWnative/.  This ensures that our brand library get's the
# native versions of any libraries it needs.  Unfortunatly this is a total
# hack since it doesn't work for suid binaries.  What we really need to do
# is enhance the linker so that when it's running on a brand linkmap it
# looks for all libraries in the brands "native" directory (for both
# regular and suid binaries).
#
NATIVE_DIR =	/.SUNWnative
CPPFLAGS +=	-D_REENTRANT -U_ASM \
		-I. -I$(BRAND_SHARED)/brand/sys -I$(UTSBASE)/common/brand/sn1
CFLAGS +=	$(CCVERBOSE)
DYNFLAGS +=	$(DYNFLAGS_$(CLASS))
DYNFLAGS +=	$(BLOCAL) $(ZNOVERSION) -Wl,-e_start
#DYNFLAGS +=	-R$(NATIVE_DIR)/lib -R$(NATIVE_DIR)/usr/lib
LDLIBS +=	-lmapmalloc -lc

ZGUIDANCE =	-zguidance=nounused
$(LIBS):= PICS += $(SHAREDOBJS)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include $(SRC)/lib/Makefile.targ
