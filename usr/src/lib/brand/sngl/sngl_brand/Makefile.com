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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2012, Joyent, Inc. All rights reserved.
#

LIBRARY =	sngl_brand.a
VERS =		.1
COBJS =		sngl_brand.o
ASOBJS =	crt.o handler.o runexe.o brand_util.o
OBJECTS =	$(COBJS)

include ../../Makefile.sngl
include $(SRC)/lib/Makefile.lib

SRCDIR =	../common
UTSBASE =	$(SRC)/uts

LIBS =		$(DYNLIB)
CSRCS =		$(COBJS:%o=../common/%c)
SHAREDOBJS =	$(ASOBJS:%o=$(ISAOBJDIR)/%o)
SRCS =		$(CSRCS)

#
# Note that the architecture specific makefiles MUST update DYNFLAGS to
# explicitly specify an interpreter for the brand emulation library so that we
# use /lib/ld.so.1 or /lib/64/ld.so.1, which in a sngl zone is the system
# linker.
# 
# Note that since the linker is used to setup processes before libc is loaded,
# it makes system calls directly (ie avoiding libc), and it makes these system
# calls before our library has been initialized. Since our library hasn't been
# initialized yet, there's no way for us to intercept and emulate any of those
# system calls. Luckily we don't have to.
#
# Note that we make sure to link our brand emulation library to libmapmalloc.
# This is required because in most cases there will be two copies of libc in
# the same process and we don't want them to fight over the heap. So for our
# brand library we link against libmapmalloc so that if we (our or copy of
# libc) try to allocate any memory it will be done via mmap() instead of brk().
#
CPPFLAGS +=	-D_REENTRANT -U_ASM \
		-I. -I$(BRAND_SHARED)/brand/sys -I$(UTSBASE)/common/brand/sngl
CFLAGS +=	$(CCVERBOSE)
DYNFLAGS +=	$(DYNFLAGS_$(CLASS))
DYNFLAGS +=	$(BLOCAL) $(ZNOVERSION) -Wl,-e_start
LDLIBS +=	-lc -lmapmalloc

$(LIBS):= PICS += $(SHAREDOBJS)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include $(SRC)/lib/Makefile.targ
