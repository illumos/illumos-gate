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
# Copyright (c) 2016 by Delphix. All rights reserved.
#

LIBRARY =	s10_brand.a
VERS =		.1
COBJS =		s10_brand.o s10_deleted.o s10_signal.o
ASOBJS =	crt.o handler.o runexe.o brand_util.o
OBJECTS =	$(COBJS)

include ../../Makefile.s10
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
# use /lib/ld.so.1 or /lib/64/ld.so.1, which in a s10 zone is the Solaris 10
# linker.  This is different from some other brands where the linker that is
# used is the native system linker (/.SUNWnative/.../ld.so.1).  We have to do
# this because the linker has a very incestuous relationship with libc and we
# don't want to use the native linker with the s10 version of libc.  (This may
# come as a surprise to the reader, but when our library is loaded it get's
# linked against the s10 version of libc.)  Although the linker interfaces are
# normally stable, there are examples, such as with the solaris8 brand, where
# we could not combine the brand's libc with the native linker.  Since we want
# to run in a known configuration, we use the S10 libc/linker combination.
#
# There is one more non-obvious side effect of using the s10 linker that
# should be mentioned.  Since the linker is used to setup processes before
# libc is loaded, it makes system calls directly (ie avoiding libc), and
# it makes these system calls before our library has been initialized.
# Since our library hasn't been initialized yet, there's no way for us
# to intercept and emulate any of those system calls.  So if any of those
# system calls ever change in the native code such that they break the s10
# linker then we're kinda screwed and will need to re-visit the current
# solution.  (The likely solution then will probably be to start using the
# native linker with our brand emulation library.)
#
# Note that we make sure to link our brand emulation library
# libmapmalloc.  This is required because in most cases there will be two
# copies of libc in the same process and we don't want them to fight over
# the heap.  So for our brand library we link against libmapmalloc so that
# if we (our or copy of libc) try to allocate any memory it will be done
# via mmap() instead of brk().
#
CPPFLAGS +=	-D_REENTRANT -U_ASM \
		-I. -I$(BRAND_SHARED)/brand/sys -I../sys \
		-I$(UTSBASE)/common/brand/solaris10 \
		-I$(SRC)/uts/common/fs/zfs
CFLAGS +=	$(CCVERBOSE)
# Needed to handle zfs include files
C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all
DYNFLAGS +=	$(DYNFLAGS_$(CLASS))
DYNFLAGS +=	$(BLOCAL) $(ZNOVERSION) -Wl,-e_start
LDLIBS +=	-lc -lmapmalloc
LINTFLAGS +=	-erroff=E_STATIC_UNUSED
LINTFLAGS64 +=	-erroff=E_STATIC_UNUSED

CERRWARN +=	-_gcc=-Wno-uninitialized

$(LIBS):= PICS += $(SHAREDOBJS)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include $(SRC)/lib/Makefile.targ
