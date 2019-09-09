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
# Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

LIBRARY=	rtld.a
VERS=		.1

COMOBJS=	rtld.o
BLTOBJ=		msg.o

OBJECTS=	$(BLTOBJ)  $(COMOBJS)

# include library definitions
include		$(SRC)/lib/Makefile.lib
include		$(SRC)/cmd/sgs/Makefile.com

SGSMSGALL=	rtld.msg

MAPFILES =	../common/mapfile
SRCS=		$(OBJECTS:%.o=../common/%.c)

BLTDEFS=	msg.h
BLTDATA=	msg.c
BLTFILES=	$(BLTDEFS) $(BLTDATA)

SGSMSGTARG=	../common/rtld.msg
SGSMSGALL=	../common/rtld.msg
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA)

CERRWARN +=	$(CNOWARN_UNINIT)

MSGSRCS=	$(COMOBJS:%.o=../common/%.c) $(BLTDATA)

FILEMODE=	555

DYNLIB=		ld.so

LIBS =		$(DYNLIB)

CPPFLAGS +=	-I. -I../common -I../../common -I../../../include \
		-I../../../include/$(MACH) \
		-I$(SRC)/lib/libc/inc \
		-I$(SRC)/uts/common/krtld \
		-I$(SRC)/common/sgsrtcid \
		-I$(SRC)/uts/$(ARCH)/sys

DYNFLAGS +=	$(VERSREF)
LDLIBS +=	$(CONVLIBDIR) -lconv -lc

ROOTMDBLIB=	$(ROOT)/usr/lib/mdb/proc
ROOTMDBLIB64=	$(ROOTMDBLIB)/$(MACH64)
ROOTMDBLIBS=	$(ROOTMDBLIB)/$(MTARG)$(DYNLIB)

CLEANFILES +=	$(BLTFILES)
