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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY =	libconv.a

COMOBJS32 =	cap32.o			dynamic32.o \
		elf32.o			globals32.o \
		phdr32.o		\
		relocate_i38632.o	relocate_amd6432.o \
		relocate_sparc32.o	sections32.o \
		symbols32.o		symbols_sparc32.o \
		syminfo32.o

COMOBJS64 =	cap64.o			dynamic64.o \
		elf64.o			globals64.o \
		phdr64.o		\
		relocate_i38664.o	relocate_amd6464.o \
		relocate_sparc64.o	sections64.o \
		symbols64.o		symbols_sparc64.o \
		syminfo64.o

COMOBJS=	arch.o			config.o \
		data.o			deftag.o \
		demangle.o		dl.o \
		dwarf_ehe.o		group.o	\
		lddstub.o		segments.o \
		version.o

COMOBJS_NOMSG =	tokens.o

COMOBJS_NOMSG32 = \
		relocate32.o
COMOBJS_NOMSG64 = \
		relocate64.o

ELFCAP_OBJS=	elfcap.o

ASOBJS=		vernote.o

OBJECTS =	$(COMOBJS) $(COMOBJS32) $(COMOBJS64) $(COMOBJS_NOMSG) \
		$(COMOBJS_NOMSG32) $(COMOBJS_NOMSG64) $(ELFCAP_OBJS) $(ASOBJS)

ELFCAP=		$(SRC)/common/elfcap

#
# This library is unusual since it's a static archive of PIC objects.
# Since static archives should never contain CTF data (regardless of
# whether the object code is position-independent), we disable CTF.
#
NOCTFOBJS =	$(OBJECTS)
CTFMERGE_LIB =	:

include 	$(SRC)/lib/Makefile.lib
include 	$(SRC)/cmd/sgs/Makefile.com

CTFCONVERT_O=

ONLDREADME=	../../packages/common/SUNWonld-README

PICS=		$(OBJECTS:%=pics/%)

CPPFLAGS +=	-I$(SRCBASE)/lib/libc/inc -I$(ELFCAP) \
		-I$(SRC)/common/sgsrtcid $(VAR_LIBCONV_CPPFLAGS)

ARFLAGS=	cr

AS_CPPFLAGS=	-P -D_ASM $(CPPFLAGS)

BLTDATA=	$(COMOBJS:%.o=%_msg.h) \
		    $(COMOBJS32:%.o=%_msg.h) $(COMOBJS64:%.o=%_msg.h)

SRCS=		../common/llib-lconv
LINTSRCS=	$(COMOBJS:%.o=../common/%.c) \
		    $(COMOBJS_NOMSG:%.o=../common/%.c) \
		    $(ELFCOM_OBJS:%.o=$(ELFCAP)/%.c) ../common/lintsup.c
LINTSRCS32 =	$(COMOBJS32:%32.o=../common/%.c)
LINTSRCS64 =	$(COMOBJS64:%64.o=../common/%.c)

VERNOTE_DEBUG= -D
$(INTERNAL_RELEASE_BUILD)VERNOTE_DEBUG=

SGSMSGTARG=	$(COMOBJS:%.o=../common/%.msg) \
		    $(COMOBJS32:%32.o=../common/%.msg) \
		    $(COMOBJS64:%64.o=../common/%.msg)

LINTFLAGS +=	-u
LINTFLAGS64 +=	-u

CLEANFILES +=	$(BLTDATA) $(LINTOUTS) bld_vernote vernote.s
CLOBBERFILES +=	$(LINTLIBS)
