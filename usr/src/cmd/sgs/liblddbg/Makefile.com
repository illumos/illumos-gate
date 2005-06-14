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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY=	liblddbg.a
VERS=		.4

COMOBJS=	args.o		bindings.o	cap.o		debug.o	\
		dynamic.o	entry.o		elf.o		files.o \
		libs.o		map.o		phdr.o \
		relocate.o	sections.o	segments.o	shdr.o \
		support.o	syms.o		audit.o		util.o \
		version.o	got.o		move.o		statistics.o \
		tls.o		unused.o
COMOBJS64=	files64.o	map64.o		relocate64.o	sections64.o \
		segments64.o	syms64.o	audit64.o	got64.o \
		move64.o	version64.o	statistics64.o	tls64.o \
		unused64.o	cap64.o
BLTOBJ=		msg.o

OBJECTS=	$(BLTOBJ)  $(COMOBJS)  $(COMOBJS64)

include		$(SRC)/lib/Makefile.lib
include		$(SRC)/cmd/sgs/Makefile.com

MAPFILES=	../common/mapfile-vers
MAPOPTS=	$(MAPFILES:%=-M%)


CPPFLAGS +=	-I$(SRCBASE)/lib/libc/inc $(VAR_LIBLDDBG_CPPFLAGS)
DYNFLAGS +=	$(VERSREF) $(CONVLIBDIR) $(ZLAZYLOAD)
LDLIBS +=	-lconv -lc
LINTFLAGS +=	-u $(CONVLIBDIR) -D_REENTRANT
LINTFLAGS64 +=	-u $(CONVLIBDIR64) -D_REENTRANT -erroff=E_CAST_INT_TO_SMALL_INT


# A bug in pmake causes redundancy when '+=' is conditionally assigned, so
# '=' is used with extra variables.
# $(DYNLIB) :=  DYNFLAGS += -Yl,$(SGSPROTO)
#
XXXFLAGS=
$(DYNLIB) :=    XXXFLAGS= $(USE_PROTO) $(MAPOPTS)
DYNFLAGS +=     $(XXXFLAGS)

native :=	MAPOPTS=
native :=	DYNFLAGS	+= $(CONVLIBDIR)

BLTDEFS=	msg.h
BLTDATA=	msg.c
BLTMESG=	$(SGSMSGDIR)/liblddbg

BLTFILES=	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM=	../common/liblddbg.msg
SGSMSGTARG=	$(SGSMSGCOM)
SGSMSGALL=	$(SGSMSGCOM)

SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n liblddbg_msg

SRCS=		../common/llib-llddbg
LIBSRCS=	$(COMOBJS:%.o=../common/%.c)  $(BLTDATA)
LIBSRCS64=	$(COMOBJS64:%64.o=%.c)
LINTSRCS=	$(LIBSRCS) ../common/lintsup.c

CLEANFILES +=	$(LINTOUTS) $(LINTLIBS) $(BLTFILES)
CLOBBERFILES +=	$(DYNLIB)  $(LINTLIBS) $(LIBLINKS)

ROOTFS_DYNLIB=	$(DYNLIB:%=$(ROOTFS_LIBDIR)/%)
