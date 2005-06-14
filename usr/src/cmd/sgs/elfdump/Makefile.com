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

PROG=		elfdump

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/sgs/Makefile.com

COMOBJ=		elfdump.o
TOOLOBJS=	leb128.o
BLTOBJ=		msg.o

OBJS=		$(BLTOBJ) $(COMOBJ) $(TOOLOBJS)

MAPFILE=	../common/mapfile-vers

CPPFLAGS=	-I. -I../../include -I../../include/$(MACH) \
		-I../../liblddbg/common \
		-I$(SRCBASE)/uts/$(ARCH)/sys \
		$(CPPFLAGS.master)
LLDFLAGS =	$(VAR_ELFDUMP_LLDFLAGS)
LLDFLAGS64 =	$(VAR_LD_LLDFLAGS64)
LDFLAGS +=	$(VERSREF) $(USE_PROTO) -M$(MAPFILE) $(LLDFLAGS) $(ZLAZYLOAD)
LDLIBS +=	$(ELFLIBDIR) -lelf $(LDDBGLIBDIR) $(LDDBG_LIB) \
		$(CONVLIBDIR) -lconv

LINTFLAGS +=	-x
LINTFLAGS64 +=	-x

BLTDEFS=	msg.h
BLTDATA=	msg.c
BLTMESG=	$(SGSMSGDIR)/elfdump

BLTFILES=	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM=	../common/elfdump.msg
SGSMSGTARG=	$(SGSMSGCOM)
SGSMSGALL=	$(SGSMSGCOM)
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n elfdump_msg

SRCS=		$(COMOBJ:%.o=../common/%.c) $(TOOLOBJS:%.o=../../tools/common/%.c) \
		$(BLTDATA)
LINTSRCS=	$(SRCS) ../common/lintsup.c

CLEANFILES +=	$(LINTOUTS) $(BLTFILES)
