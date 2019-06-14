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
# Copyright 2016 RackTop Systems.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

LIBRARY =	liblddbg.a
VERS =		.4

COMOBJS =	args.o		audit.o		basic.o		debug.o \
		syminfo.o	tls.o

COMOBJS32 =	bindings32.o	cap32.o		dlfcns32.o	dynamic32.o \
		elf32.o		entry32.o	files32.o	got32.o \
		libs32.o	map32.o		move32.o	phdr32.o \
		relocate32.o	sections32.o	segments32.o	shdr32.o \
		statistics32.o	support32.o	syms32.o	unused32.o \
		util32.o	version32.o

COMOBJS64 =	bindings64.o	cap64.o		dlfcns64.o	dynamic64.o \
		elf64.o		entry64.o	files64.o	got64.o \
		libs64.o	map64.o		move64.o	phdr64.o \
		relocate64.o	sections64.o	segments64.o	shdr64.o \
		statistics64.o	support64.o	syms64.o	unused64.o \
		util64.o	version64.o

BLTOBJ =	msg.o

SGSCOMMONOBJ =	alist.o

OBJECTS =	$(BLTOBJ) $(COMOBJS) $(COMOBJS32) $(COMOBJS64) $(SGSCOMMONOBJ)


include		$(SRC)/lib/Makefile.lib
include		$(SRC)/cmd/sgs/Makefile.com

SRCDIR =	$(SGSHOME)/liblddbg
MAPFILEDIR =	$(SRCDIR)/common

CERRWARN +=	-_gcc=-Wno-unused-value
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-parentheses

CPPFLAGS +=	-I$(SRC)/lib/libc/inc
DYNFLAGS +=	$(VERSREF) '-R$$ORIGIN'
LDLIBS +=	$(CONVLIBDIR) -lconv -lc

BLTDEFS =	msg.h
BLTDATA =	msg.c
BLTMESG =	$(SGSMSGDIR)/liblddbg

BLTFILES =	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM =	$(SRCDIR)/common/liblddbg.msg
SGSMSGALL =	$(SGSMSGCOM)
SGSMSGTARG =	$(SGSMSGCOM)
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n liblddbg_msg

CHKSRCS =	$(COMOBJS32:%32.o=$(SRCDIR)/common/%.c)

LIBSRCS =	$(COMOBJS:%.o=$(SRCDIR)/common/%.c) \
		$(SGSCOMMONOBJ:%.o=$(SGSCOMMON)/%.c) $(BLTDATA)

CLEANFILES +=	$(BLTFILES)
CLOBBERFILES +=	$(DYNLIB) $(LIBLINKS)

ROOTFS_DYNLIB =	$(DYNLIB:%=$(ROOTFS_LIBDIR)/%)
