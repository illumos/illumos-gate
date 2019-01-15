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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG=		crle

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/sgs/Makefile.com

COMOBJ=		config.o	crle.o 		depend.o	dump.o \
		inspect.o	hash.o		print.o		util.o
BLTOBJ=		msg.o
TOOLSOBJ=	alist.o

OBJS=		$(BLTOBJ) $(COMOBJ) $(TOOLSOBJ)

MAPFILE=	$(MAPFILE.NGB)
MAPOPT=		$(MAPFILE:%=-M%)

# not linted
SMATCH=off

CPPFLAGS +=	-I$(SRC)/common/sgsrtcid -I$(SRCBASE)/uts/$(ARCH)/sys \
		-D__EXTENSIONS__
LLDFLAGS =	'-R$$ORIGIN/../lib'
LLDFLAGS64 =	'-R$$ORIGIN/../../lib/$(MACH64)'
LDFLAGS +=	$(VERSREF) $(CC_USE_PROTO) $(MAPOPT) \
			$(LLDFLAGS) $(ZNOLAZYLOAD)
LDLIBS +=	-lelf $(CONVLIBDIR) $(CONV_LIB) $(DLLIB)
LINTFLAGS +=	-x
LINTFLAGS64 +=	-x

BLTDEFS=        msg.h
BLTDATA=        msg.c
BLTMESG=        $(SGSMSGDIR)/crle

BLTFILES=	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM=	../common/crle.msg
SGSMSGTARG=	$(SGSMSGCOM)
SGSMSGALL=	$(SGSMSGCOM)

SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n crle_msg

SRCS=		$(COMOBJ:%.o=../common/%.c) $(BLTDATA) \
		$(TOOLSOBJ:%.o=$(SGSTOOLS)/common/%.c)
LINTSRCS=	$(SRCS) ../common/lintsup.c

CLEANFILES +=	$(SGSLINTOUT) $(BLTFILES)
