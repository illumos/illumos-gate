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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY=	libcrle.a
VERS=		.1

COMOBJS=	audit.o		dump.o		util.o
BLTOBJ=		msg.o

OBJECTS=	$(BLTOBJ)  $(COMOBJS)


include		$(SRC)/lib/Makefile.lib
include		$(SRC)/cmd/sgs/Makefile.com

SRCDIR =	../common

# Building SUNWonld results in a call to the `package' target.  Requirements
# needed to run this application on older releases are established:
#   dlopen/dlclose requires libdl.so.1 prior to 5.10
# 
DLLIB =		$(VAR_DL_LIB)
package	:=	DLLIB = $(VAR_PKG_DL_LIB)

lint :=		ZRECORD =
LDLIBS +=	$(ZRECORD) -lmapmalloc $(DLLIB) -lc

LINTFLAGS +=	-u
LINTFLAGS64 +=	-u

CPPFLAGS +=	-I$(SRCBASE)/lib/libc/inc -I$(SRC)/common/sgsrtcid
DYNFLAGS +=	$(VERSREF) $(CONVLIBDIR) -lconv $(USE_PROTO)


BLTDEFS=	msg.h
BLTDATA=	msg.c
BLTMESG=	$(SGSMSGDIR)/libcrle

BLTFILES=	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM=	../common/libcrle.msg
SGSMSGALL=	$(SGSMSGCOM)
SGSMSGTARG=	$(SGSMSGCOM)
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n libcrle_msg

LIBSRCS=	$(COMOBJS:%.o=../common/%.c)  $(BLTDATA)
LINTSRCS=	$(LIBSRCS)

CLEANFILES +=	$(LINTOUTS) $(BLTFILES)
CLOBBERFILES +=	$(DYNLIB) $(LINTLIB) $(LIBLINKS)

ROOTDYNLIB=	$(DYNLIB:%=$(ROOTLIBDIR)/%)
