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
#

PROG=		elfdump

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/sgs/Makefile.com

COMOBJ =	main.o			corenote.o \
		dwarf.o			struct_layout.o \
		struct_layout_i386.o 	struct_layout_amd64.o \
		struct_layout_sparc.o 	struct_layout_sparcv9.o

COMOBJ32 =	elfdump32.o fake_shdr32.o

COMOBJ64 =	elfdump64.o fake_shdr64.o

TOOLOBJ =	leb128.o

BLTOBJ =	msg.o

OBJS=		$(BLTOBJ) $(COMOBJ) $(COMOBJ32) $(COMOBJ64) $(TOOLOBJ)

MAPFILE=	$(MAPFILE.NGB)
MAPOPT=		$(MAPFILE:%=-M%)

CPPFLAGS=	-I. -I../common -I../../include -I../../include/$(MACH) \
		-I$(SRCBASE)/lib/libc/inc -I$(SRCBASE)/uts/$(ARCH)/sys \
		$(CPPFLAGS.master) -I$(ELFCAP)
LLDFLAGS =	$(VAR_ELFDUMP_LLDFLAGS)
LLDFLAGS64 =	$(VAR_ELFDUMP_LLDFLAGS64)
LDFLAGS +=	$(VERSREF) $(CC_USE_PROTO) $(MAPOPT) $(LLDFLAGS)
LDLIBS +=	$(ELFLIBDIR) -lelf $(LDDBGLIBDIR) $(LDDBG_LIB) \
		    $(CONVLIBDIR) $(CONV_LIB)

LINTFLAGS +=	-x
LINTFLAGS64 +=	-x

CERRWARN +=	-_gcc=-Wno-uninitialized

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
		$(TOOLOBJ:%.o=../../tools/common/%.c) $(BLTDATA)
LINTSRCS =	$(SRCS) ../common/lintsup.c

CLEANFILES +=	$(LINTOUTS) $(BLTFILES) gen_struct_layout
