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

LIBRARY=	librtld.a
VERS=		.1

MACHOBJS=	_relocate.o
COMOBJS=	dldump.o	dynamic.o	relocate.o	syms.o \
		util.o
BLTOBJ=		msg.o

OBJECTS=	$(BLTOBJ)  $(MACHOBJS)  $(COMOBJS)


include		$(SRC)/lib/Makefile.lib
include		$(SRC)/cmd/sgs/Makefile.com

SRCDIR =	../common
CPPFLAGS +=	-I../../rtld/common -I$(SRCBASE)/lib/libc/inc \
		-I$(SRCBASE)/uts/common/krtld -I$(SRC)/common/sgsrtcid \
		-I$(SRCBASE)/uts/sparc
DYNFLAGS +=	$(VERSREF) $(ZLAZYLOAD) '-R$$ORIGIN'
LDLIBS +=	$(CONVLIBDIR) $(CONV_LIB) $(ELFLIBDIR) -lelf -lc

LINTFLAGS +=	-u -erroff=E_NAME_DECL_NOT_USED_DEF2
LINTFLAGS64 +=	-u -erroff=E_NAME_DECL_NOT_USED_DEF2

# A bug in pmake causes redundancy when '+=' is conditionally assigned, so
# '=' is used with extra variables.
#
XXXFLAGS=
$(DYNLIB) :=	XXXFLAGS= $(USE_PROTO)
DYNFLAGS +=	$(XXXFLAGS)


BLTDEFS=	msg.h
BLTDATA=	msg.c
BLTMESG=	$(SGSMSGDIR)/librtld

BLTFILES=	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM=	../common/librtld.msg
SGSMSGALL=	$(SGSMSGCOM)
SGSMSGTARG=	$(SGSMSGCOM)
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n librtld_msg

SRCS=		../common/llib-lrtld
LINTSRCS=	$(MACHOBJS:%.o=%.c)  $(COMOBJS:%.o=../common/%.c) \
		$(BLTDATA) ../common/lintsup.c

CLEANFILES +=	$(BLTFILES) $(LINTOUTS)
CLOBBERFILES +=	$(DYNLIB) $(LINTLIB) $(LIBLINKS)

ROOTFS_DYNLIB=	$(DYNLIB:%=$(ROOTFS_LIBDIR)/%)
