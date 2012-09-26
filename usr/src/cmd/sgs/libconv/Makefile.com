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
# Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
#

LIBRARY =	libconv.a

COMOBJS32 =	cap_machelf32.o		dynamic_machelf32.o \
		globals_machelf32.o 	sections_machelf32.o \
		symbols_machelf32.o	symbols_sparc_machelf32.o

COMOBJS64 =	cap_machelf64.o		dynamic_machelf64.o \
		globals_machelf64.o	sections_machelf64.o \
		symbols_machelf64.o	symbols_sparc_machelf64.o

COMOBJS=	arch.o			audit.o \
		c_literal.o \
		cap.o			config.o \
		corenote.o 		data.o \
		deftag.o 		demangle.o \
		dl.o			dwarf.o \
		dwarf_ehe.o 		dynamic.o \
		elf.o			entry.o \
		globals.o		group.o \
 		lddstub.o		map.o \
		phdr.o			relocate.o \
 		relocate_i386.o		relocate_amd64.o \
		relocate_sparc.o	sections.o \
		segments.o    		strproc.o \
		symbols.o  		syminfo.o \
  		tokens.o  		time.o \
		version.o

ELFCAP_OBJS=	elfcap.o

ASOBJS=		vernote.o

BLTOBJS=	arch_msg.o		audit_msg.o \
		c_literal_msg.o \
		cap_msg.o		config_msg.o \
		corenote_msg.o		data_msg.o \
		deftag_msg.o		demangle_msg.o \
		dl_msg.o		dwarf_msg.o \
		dwarf_ehe_msg.o 	dynamic_msg.o \
		elf_msg.o 		entry_msg.o \
		globals_msg.o		group_msg.o \
 		map_msg.o		lddstub_msg.o \
		phdr_msg.o 		relocate_amd64_msg.o \
		relocate_i386_msg.o	relocate_sparc_msg.o \
		sections_msg.o 		segments_msg.o \
		symbols_msg.o 		symbols_sparc_msg.o \
		syminfo_msg.o 		time_msg.o \
		version_msg.o


OBJECTS =	$(COMOBJS) $(COMOBJS32) $(COMOBJS64) $(ELFCAP_OBJS) \
		$(ASOBJS) $(BLTOBJS)

#
# This library is unusual since it's a static archive of PIC objects.
# Since static archives should never contain CTF data (regardless of
# whether the object code is position-independent), we disable CTF.
#
NOCTFOBJS =	$(OBJECTS)
CTFMERGE_LIB =	:

include 	$(SRC)/lib/Makefile.lib
include 	$(SRC)/cmd/sgs/Makefile.com

CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-switch

CTFCONVERT_O=

README_REVISION=../../packages/common/readme_revision
ONLDREADME=	../../packages/common/SUNWonld-README

PICS=		$(OBJECTS:%=pics/%)

CPPFLAGS +=	-I$(SRCBASE)/lib/libc/inc -I$(ELFCAP) \
		-I$(SRC)/common/sgsrtcid

ARFLAGS=	cr

AS_CPPFLAGS=	-P -D_ASM $(CPPFLAGS)

BLTDATA=	$(BLTOBJS:%.o=%.c) $(BLTOBJS:%.o=%.h) report_bufsize.h

SRCS=		../common/llib-lconv
LINTSRCS=	$(COMOBJS:%.o=../common/%.c) \
		    $(COMOBJS_NOMSG:%.o=../common/%.c) \
		    $(ELFCOM_OBJS:%.o=$(ELFCAP)/%.c) ../common/lintsup.c
LINTSRCS32 =	$(COMOBJS32:%32.o=../common/%.c)
LINTSRCS64 =	$(COMOBJS64:%64.o=../common/%.c)

# INTERNAL_RELEASE_BUILD is defined by standard full builds (nightly),
# but not for sgs builds we do for development. The result of these
# two lines is that dev builds pass -d to the readme_revision script,
# generating a more detailed version string for the linker components
# that includes the workspace, user, CR, and date. Official builds get
# a simpler uncluttered version string.
VERNOTE_DEBUG= -d
$(INTERNAL_RELEASE_BUILD)VERNOTE_DEBUG=

SGSMSGTARG=	$(BLTOBJS:%_msg.o=../common/%.msg)

LINTFLAGS +=	-u
LINTFLAGS64 +=	-u

CLEANFILES +=	$(BLTDATA) $(LINTOUTS) bld_vernote vernote.s
CLOBBERFILES +=	$(LINTLIBS)
