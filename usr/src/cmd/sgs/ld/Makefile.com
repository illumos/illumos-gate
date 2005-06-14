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

PROG=		ld

include 	$(SRC)/cmd/Makefile.cmd
include 	$(SRC)/cmd/sgs/Makefile.com

COMOBJS=	ld.o
BLTOBJ=		msg.o

OBJS =		$(BLTOBJ) $(MACHOBJS) $(COMOBJS)
.PARALLEL:	$(OBJS)

MAPFILE=	../common/mapfile-vers

# Building SUNWonld results in a call to the `package' target.  Requirements
# needed to run this application on older releases are established:
#   dlopen/dlclose requires libdl.so.1 prior to 5.10
# 
DLLIB =		$(VAR_DL_LIB)
package	:=	DLLIB = $(VAR_PKG_DL_LIB)

LLDFLAGS =	$(VAR_LD_LLDFLAGS)
LLDFLAGS64 =	$(VAR_LD_LLDFLAGS64)
LDFLAGS +=	$(VERSREF) $(LAZYLOAD) $(BDIRECT) \
			$(USE_PROTO) -M$(MAPFILE)
LLDLIBS=	-lelf $(DLLIB) $(CONVLIBDIR) -lconv
LLDLIBS64=	-lelf $(DLLIB) $(CONVLIBDIR64) -lconv

LDFLAGS +=	$(LLDFLAGS)
LDLIBS +=	$(LLDLIBS)
LINTFLAGS +=	-x
LINTFLAGS64 +=	-x
CLEANFILES +=	$(LINTOUTS)

native :=	LDFLAGS = -R$(SGSPROTO) $(ZNOVERSION)
native :=	LLDLIBS = -L$(SGSPROTO) -lelf -ldl $(CONVLIBDIR) \
			-lconv $(VAR_LD_NATIVE_LLDLIBS)

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

ROOTCCSBIN=	$(ROOT)/usr/ccs/bin
ROOTCCSBINPROG=	$(PROG:%=$(ROOTCCSBIN)/%)

CLEANFILES +=	$(BLTFILES)

FILEMODE=	0755
