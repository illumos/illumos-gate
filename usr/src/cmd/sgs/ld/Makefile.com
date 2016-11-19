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
#

PROG =		ld

include 	$(SRC)/cmd/Makefile.cmd
include 	$(SRC)/cmd/sgs/Makefile.com

COMOBJS =	ld.o
BLTOBJ =	msg.o

OBJS =		$(BLTOBJ) $(COMOBJS)
.PARALLEL:	$(OBJS)

MAPFILES =	../common/mapfile-intf $(MAPFILE.NGB)
MAPOPTS =	$(MAPFILES:%=-M%)

LDFLAGS +=	$(VERSREF) $(CC_USE_PROTO) $(MAPOPTS) $(VAR_LD_LLDFLAGS)
LDLIBS +=	$(LDLIBDIR) $(LD_LIB) $(ELFLIBDIR) -lelf \
		    $(LDDBGLIBDIR) $(LDDBG_LIB) $(CONVLIBDIR) $(CONV_LIB)

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-parentheses

LINTFLAGS +=	-x
LINTFLAGS64 +=	-x $(VAR_LINTFLAGS64)

CLEANFILES +=	$(LINTOUTS)

native :=	LDFLAGS = -R$(SGSPROTO) $(ZNOVERSION)
native :=	LDLIBS = -L$(SGSPROTO) $(LD_LIB) -lelf $(CONVLIBDIR) \
		    $(CONV_LIB)
native :=	CPPFLAGS += -DNATIVE_BUILD

BLTDEFS=	msg.h
BLTDATA=	msg.c
BLTMESG=	$(SGSMSGDIR)/ld

BLTFILES=	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM=	../common/ld.msg
SGSMSGTARG=	$(SGSMSGCOM)
SGSMSGALL=	$(SGSMSGCOM)
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n ld_msg

SRCS=		$(MACHOBJS:%.o=%.c)  $(COMOBJS:%.o=../common/%.c)  $(BLTDATA)
LINTSRCS=	$(SRCS) ../common/lintsup.c

CLEANFILES +=	$(BLTFILES)

FILEMODE=	0755
