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
# Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2024 Oxide Computer Company
#

PROG=		elfdump

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/sgs/Makefile.com
include		$(SRC)/common/hexdump/Makefile.com

COMOBJ =	main.o			corenote.o \
		dwarf.o			struct_layout.o \
		struct_layout_i386.o	struct_layout_amd64.o \
		struct_layout_sparc.o	struct_layout_sparcv9.o

COMOBJ32 =	elfdump32.o fake_shdr32.o

COMOBJ64 =	elfdump64.o fake_shdr64.o

SGSCOMMONOBJ =	leb128.o

BLTOBJ =	msg.o

EXTOBJ =	$(HEXDUMP_OBJS)

OBJS=		$(BLTOBJ) $(COMOBJ) $(COMOBJ32) $(COMOBJ64) $(SGSCOMMONOBJ) \
		$(EXTOBJ)

MAPFILE=	$(MAPFILE.NGB)
MAPOPT=		$(MAPFILE:%=-Wl,-M%)

CPPFLAGS=	-I. -I../common -I../../include -I../../include/$(MACH) \
		-I$(SRC)/lib/libc/inc -I$(SRC)/uts/$(ARCH)/sys \
		$(CPPFLAGS.master) -I$(ELFCAP)

LDFLAGS +=	$(VERSREF) $(MAPOPT) '-R$$ORIGIN/../../lib/$(MACH64)'
LDLIBS +=	$(ELFLIBDIR64) -lelf $(LDDBGLIBDIR64) -llddbg \
		    $(CONVLIBDIR64) -lconv

NATIVE_LDFLAGS = $(LDASSERTS) $(BDIRECT)

BLTDEFS =	msg.h
BLTDATA =	msg.c
BLTMESG =	$(SGSMSGDIR)/elfdump

BLTFILES =	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM =	../common/elfdump.msg
SGSMSGTARG =	$(SGSMSGCOM)
SGSMSGALL =	$(SGSMSGCOM)
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n elfdump_msg

SRCS =		$(COMOBJ:%.o=../common/%.c) \
		$(COMOBJ32:%32.o=../common/%.c) \
		$(SGSCOMMONOBJ:%.o=$(SGSCOMMON)/%.c) $(BLTDATA)

CLEANFILES +=	$(BLTFILES) gen_struct_layout
