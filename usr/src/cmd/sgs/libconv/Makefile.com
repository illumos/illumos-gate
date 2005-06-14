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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY=	libconv.a

COMOBJS_MSG=	arch.o			config.o \
		data.o			deftag.o \
		dl.o			dynamic.o \
		elf.o			globals.o \
		dwarf_ehe.o \
		cap.o			group.o \
		relocate_amd64.o \
		lddstub.o		phdr.o \
		relocate_i386.o		relocate_sparc.o \
		sections.o		segments.o \
		symbols.o		symbols_sparc.o \
		version.o

COMOBJS_NOMSG=	relocate.o		tokens.o

ELFCAP_OBJS=	elfcap.o

ASOBJS=		vernote.o

OBJECTS=	$(COMOBJS_MSG) $(COMOBJS_NOMSG) $(ELFCAP_OBJS) $(ASOBJS)

ELFCAP=		$(SRC)/common/elfcap

#
# This library is unusual since it's a static archive of PIC objects.
# Since static archives should never contain CTF data (regardless of
# whether the object code is position-independent), we disable CTF.
#
NOCTFOBJS=	$(OBJECTS)
CTFMERGE_LIB=	:

include 	$(SRC)/lib/Makefile.lib
include 	$(SRC)/cmd/sgs/Makefile.com

CTFCONVERT_O=

ONLDREADME=	../../packages/common/SUNWonld-README

PICS=		$(OBJECTS:%=pics/%)

CPPFLAGS +=	-I$(ELFCAP) $(VAR_LIBCONV_CPPFLAGS)
ARFLAGS=	cr

AS_CPPFLAGS=	-P -D_ASM $(CPPFLAGS)

BLTDATA=	$(COMOBJS_MSG:%.o=%_msg.h)

SRCS=		../common/llib-lconv
LINTSRCS=	$(COMOBJS_MSG:%.o=../common/%.c) \
		$(COMOBJS_NOMSG:%.o=../common/%.c) \
		$(ELFCOM_OBJS:%.o=$(ELFCAP)/%.c) \
		../common/lintsup.c

VERNOTE_DEBUG= -D
$(INTERNAL_RELEASE_BUILD)VERNOTE_DEBUG=

SGSMSGTARG=	$(COMOBJS_MSG:%.o=../common/%.msg)

LINTFLAGS +=	-u
LINTFLAGS64 +=	-u

CLEANFILES +=	$(BLTDATA) $(LINTOUTS) bld_vernote vernote.s
CLOBBERFILES +=	$(LINTLIB)
