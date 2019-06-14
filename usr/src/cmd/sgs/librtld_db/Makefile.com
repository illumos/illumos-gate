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
# Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

LIBRARY=	librtld_db.a
VERS=		.1

COMOBJS=	rtld_db.o	rd_elf.o
BLTOBJ=		msg.o

OBJECTS =	$(BLTOBJ) $(COMOBJS) $(COMOBJS64) $(PLTOBJS)

include		$(SRC)/lib/Makefile.lib
include		$(SRC)/cmd/sgs/Makefile.com

SRCDIR =	../common

CPPFLAGS +=	-I$(SRC)/lib/libc/inc
DYNFLAGS +=	$(VERSREF)
LDLIBS +=	$(CONVLIBDIR) -lconv -lc

CERRWARN +=	$(CNOWARN_UNINIT)

BLTDEFS=	msg.h
BLTDATA=	msg.c

BLTFILES=	$(BLTDEFS) $(BLTDATA)

SGSMSGCOM=	../common/librtld_db.msg
SGSMSGINTEL=	../common/librtld_db.intel.msg
SGSMSGSPARCV9=	../common/librtld_db.sparcv9.msg
SGSMSGTARG=	$(SGSMSGCOM)
SGSMSGALL=	$(SGSMSGCOM)
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA)

MSGSRCS=	$(COMOBJS:%.o=../common/%.c) $(PLTSRCS) $(BLTDATA)

CLEANFILES +=	$(BLTFILES)
CLOBBERFILES +=	$(DYNLIB)

ROOTFS_DYNLIB=	$(DYNLIB:%=$(ROOTFS_LIBDIR)/%)
ROOTFS_LINKS=	$(ROOTFS_LIBDIR)/$(LIBLINKS)

ROOTFS_DYNLIB64=	$(DYNLIB:%=$(ROOTFS_LIBDIR64)/%)
ROOTFS_LINKS64=		$(ROOTFS_LIBDIR64)/$(LIBLINKS)

$(ROOTFS_DYNLIB) :=	FILEMODE= 755
$(ROOTFS_DYNLIB64) :=	FILEMODE= 755

pics/rd_elf.o :=	CERRWARN += -erroff=E_END_OF_LOOP_CODE_NOT_REACHED
pics/rd_elf64.o :=	CERRWARN += -erroff=E_END_OF_LOOP_CODE_NOT_REACHED
