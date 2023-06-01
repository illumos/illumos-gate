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
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

# Object lists are organized into primary (most frequently used code) and
# secondary lists (less frequently used code).

P_COMOBJS=	debugdata.o \
		analyze.o	elf.o		external.o	globals.o \
		malloc.o	paths.o		setup.o		util.o \
		dlfcns.o	config_elf.o	locale.o	tsort.o \
		remove.o	move.o		tls.o		cap.o

S_COMOBJS=	debug.o		audit.o		object.o

G_MACHOBJS=	doreloc.o

P_MACHOBJS=	sparc_elf.o	_setup.o

CP_MACHOBJS=	common_sparc.o

S_MACHOBJS=

P_ASOBJS=	boot.o		boot_elf.o	caller.o

S_ASOBJS=

CRTSRCS=	../../../../lib/crt/sparc
CRTI=		pics/crti.o
CRTN=		pics/crtn.o
CRTS=		$(CRTI)		$(CRTN)

CHKSRCS=	$(SRC)/uts/common/krtld/reloc.h

BASEPLAT =	sparc

include		$(SRC)/Makefile.master

MAPFILE-ORDER =	../common/mapfile-order-gcc

include		$(SRC)/cmd/sgs/rtld/Makefile.com
include		$(SRC)/lib/Makefile.lib.64

# Add any machine specific flags.

CPPFLAGS +=	-I../../../../uts/sparc/krtld
ASFLAGS +=	-s $(AS_PICFLAGS) -D__sparcv9 -D_ELF64 $(sparcv9_XARCH)
ADBGENFLAGS +=	-mlp64
ADBSUB=		$(ADBSUB64)
CPPFLAGS +=	-D_ELF64
SONAME=		/lib/sparcv9/ld.so.1

SGSMSGTARG +=	$(SGSMSGSPARC) $(SGSMSGSPARC64) $(SGSMSG64)

LDLIB =		-L ../../libld/$(MACH64)
RTLDLIB =	-L ../../librtld/$(MACH64)

CPICLIB =	$(CPICLIB64)
LDDBGLIBDIR =	$(LDDBGLIBDIR64)
CONVLIBDIR =	$(CONVLIBDIR64)


.KEEP_STATE:

all:		$(RTLD)

install:	all $(ROOTDYNLIB64) $(ROOTCOMPATLINKS64)

adbmacros:	adb .WAIT $(ADBSCRIPTS)

adbinstall:	adbmacros .WAIT $(ROOTADB64)

pics/%.o:	../sparc/%.c
		$(COMPILE.c) -o $@ $<
		$(POST_PROCESS_O)

include		$(SRC)/cmd/sgs/rtld/Makefile.targ
include		$(SRC)/Makefile.master.64
