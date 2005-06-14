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
# Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY=	rtld.a
VERS=		.1


COMOBJS=	rtld.o
BLTOBJ=		msg.o

OBJECTS= 	$(BLTOBJ)  $(COMOBJS)


# include library definitions
include 	$(SRC)/lib/Makefile.lib
include		../../../Makefile.com

SRCBASE=	../../../../..

SGSMSGALL=	rtld.msg

MAPFILE=	../common/mapfile
SRCS=		$(OBJECTS:%.o=../common/%.c)

BLTDEFS=	msg.h
BLTDATA=	msg.c
BLTFILES=	$(BLTDEFS) $(BLTDATA)

SGSMSGTARG=	../common/rtld.msg
SGSMSGALL=	../common/rtld.msg
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA)

LINTFLAGS +=	-u -erroff=E_NAME_DECL_NOT_USED_DEF2
LINTFLAGS64 += 	-u -erroff=E_NAME_DECL_NOT_USED_DEF2

LINTSRCS=	$(COMOBJS:%.o=../common/%.c) $(BLTDATA)

GROUP=		sys
FILEMODE=	555

DYNLIB=		ld.so

LIBS =		$(DYNLIB) $(LINTLIB)
$(VAR_POUND_2)LIBS += $(LIBRARY)

# definitions for lint

CFLAGS +=	
CFLAGS64 +=
CPPFLAGS +=	-I. -I../common -I../../common -I../../../include \
		-I../../../include/$(MACH) \
		-I$(SRCBASE)/lib/libc/inc \
		-I$(SRCBASE)/uts/common/krtld \
		-I$(SRCBASE)/uts/$(ARCH)/sys

CPPFLAGS64 +=
DYNFLAGS +=	$(VERSREF) -M $(MAPFILE)
LDLIBS +=	$(CONVLIBDIR) -lconv -lc

ROOTMDBLIB=	$(ROOT)/usr/lib/mdb/proc
ROOTMDBLIB64=	$(ROOTMDBLIB)/$(MACH64)
ROOTMDBLIBS=	$(ROOTMDBLIB)/$(MTARG)$(DYNLIB)

CLEANFILES +=	$(LINTOUTS) $(BLTFILES)
