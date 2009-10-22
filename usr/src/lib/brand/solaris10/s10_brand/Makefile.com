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
#

LIBRARY =	s10_brand.a
VERS =		.1
COBJS =		s10_brand.o
ASOBJS =	s10_crt.o s10_handler.o s10_runexe.o
OFFSETS_SRC =	../common/offsets.in
OFFSETS_H =	assym.h
OBJECTS =	$(COBJS) $(ASOBJS)
CLOBBERFILES +=	$(OFFSETS_H)

include ../../Makefile.s10
include $(SRC)/lib/Makefile.lib

SRCDIR =	../common
UTSBASE =	$(SRC)/uts

LIBS =		$(DYNLIB)
CSRCS =		$(COBJS:%o=../common/%c)
ASSRCS =	$(ASOBJS:%o=$(ISASRCDIR)/%s)
SRCS =		$(CSRCS) $(ASSRCS)

#
# Ugh, this is a gross hack.  Our assembly routines uses lots of defines
# to simplify variable access.  All these defines work fine for amd64
# compiles because when compiling for amd64 we use the GNU assembler,
# gas.  For 32-bit code we use the Sun assembler, as.  Unfortunatly
# as does not handle certian constructs that gas does.  So rather than
# make our code less readable, we'll just use gas to compile our 32-bit
# code as well.
#
i386_AS		= $(amd64_AS)

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
		-I. -I../sys -I$(UTSBASE)/common/brand/solaris10 \
		-I$(SRC)/uts/common/fs/zfs
CFLAGS +=	$(CCVERBOSE)
# Needed to handle zfs include files
C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all
ASFLAGS =	-P $(ASFLAGS_$(CURTYPE)) -D_ASM -I. -I../sys
DYNFLAGS +=	$(DYNFLAGS_$(CLASS))
DYNFLAGS +=	$(BLOCAL) $(ZNOVERSION) -Wl,-e_start
LDLIBS +=	-lc -lmapmalloc

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

#
# build the offset header before trying to compile any files.  (it's included
# by s10_misc.h, so it's needed for all objects, not just assembly ones.)
#
$(OBJECTS:%=pics/%): $(OFFSETS_H)
$(OFFSETS_H): $(OFFSETS_SRC)
	$(OFFSETS_CREATE) $(CTF_FLAGS) < $(OFFSETS_SRC) >$@

pics/%.o: $(ISASRCDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
