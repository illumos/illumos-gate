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

PROG =		ld

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/sgs/Makefile.com

COMOBJS =	ld.o
BLTOBJ =	msg.o

OBJS =		$(BLTOBJ) $(COMOBJS)
.PARALLEL:	$(OBJS)

SRCDIR =	$(SGSHOME)/ld

MAPFILES =	$(SRCDIR)/common/mapfile-intf $(MAPFILE.NGB)
MAPOPTS =	$(MAPFILES:%=-M%)

LDFLAGS +=	$(VERSREF) $(MAPOPTS) $(VAR_LD_LLDFLAGS)
LDLIBS +=	$(LDLIBDIR) -lld $(ELFLIBDIR) -lelf \
		    $(LDDBGLIBDIR) -llddbg $(CONVLIBDIR) -lconv

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-parentheses

BLTDEFS=	msg.h
BLTDATA=	msg.c
BLTMESG=	$(SGSMSGDIR)/ld

BLTFILES=	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM=	$(SRCDIR)/common/ld.msg
SGSMSGTARG=	$(SGSMSGCOM)
SGSMSGALL=	$(SGSMSGCOM)
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n ld_msg

SRCS=		$(MACHOBJS:%.o=%.c)  $(COMOBJS:%.o=$(SRCDIR)/common/%.c)  $(BLTDATA)

CLEANFILES +=	$(BLTFILES)

FILEMODE=	0755
