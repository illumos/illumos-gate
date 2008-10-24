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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY =	sn1_brand.a
VERS =		.1
COBJS =		sn1_brand.o
ASOBJS =	sn1_crt.o sn1_handler.o sn1_runexe.o
OFFSETS_SRC =	../common/offsets.in
OFFSETS_H =	assym.h
OBJECTS =	$(COBJS) $(ASOBJS)
CLOBBERFILES +=	$(OFFSETS_H)

include ../../Makefile.sn1
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
CPPFLAGS +=	-D_REENTRANT -U_ASM -I. -I../sys -I$(UTSBASE)/common/brand/sn1
CFLAGS +=	$(CCVERBOSE)
ASFLAGS =	-P $(ASFLAGS_$(CURTYPE)) -D_ASM -I. -I../sys
DYNFLAGS +=	$(DYNFLAGS_$(CLASS))
DYNFLAGS +=	$(BLOCAL) $(ZNOVERSION) -Wl,-e_start
#DYNFLAGS +=	-R$(NATIVE_DIR)/lib -R$(NATIVE_DIR)/usr/lib
LDLIBS +=	-lc -lmapmalloc

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

#
# build the offset header before trying to compile any files.  (it's included
# by sn1_misc.h, so it's needed for all objects, not just assembly ones.)
#
$(OBJECTS:%=pics/%): $(OFFSETS_H)
$(OFFSETS_H): $(OFFSETS_SRC)
	$(OFFSETS_CREATE) $(CTF_FLAGS) < $(OFFSETS_SRC) >$@

pics/%.o: $(ISASRCDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
