#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.

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
# cmd/sgs/gprof/Makefile.com
#

PROG=		gprof

include 	$(SRC)/cmd/Makefile.cmd
include 	$(SRC)/cmd/sgs/Makefile.com

COMOBJS=	gprof.o arcs.o dfn.o lookup.o calls.o \
		printgprof.o printlist.o readelf.o

OBJS=		$(COMOBJS)
BLURBS=		gprof.callg.blurb gprof.flat.blurb
SRCS=		$(COMOBJS:%.o=../common/%.c)

INCLIST=	-I../common -I../../include -I../../include/$(MACH)
DEFLIST=	-DELF_OBJ -DELF
CPPFLAGS=	$(INCLIST) $(DEFLIST) $(CPPFLAGS.master) -I$(ELFCAP)
CFLAGS +=	$(CCVERBOSE)
CSTD=	$(CSTD_GNU99)
LDLIBS +=	$(CONVLIBDIR) $(CONV_LIB) $(ELFLIBDIR) -lelf
LINTSRCS =	$(SRCS)
LINTFLAGS +=	-x
CERRWARN +=	-_gcc=-Wno-uninitialized
CLEANFILES +=	$(LINTOUTS)

ROOTLIBBLURB=	$(BLURBS:%=$(ROOTSHLIBCCS)/%)

$(ROOTLIBBLURB) :=	FILEMODE=	444

%.o:		../common/%.c
		$(COMPILE.c) $<
.PARALLEL: $(OBJS)
