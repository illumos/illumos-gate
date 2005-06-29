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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/sgs/yacc/Makefile.com
#

COMOBJS=	y1.o y2.o y3.o y4.o
WHATOBJS=	whatdir.o
POBJECTS=	$(COMOBJS) $(WHATOBJS)
POBJS=		$(POBJECTS:%=objs/%)

OBJECTS=	libmai.o libzer.o

LIBRARY=	liby.a
VERS=		.1
YACCPAR=	yaccpar

# 32-bit environment mapfile
MAPFILE=	../common/mapfile-vers

include ../../../../lib/Makefile.lib

# Override default source file derivation rule (in Makefile.lib)
# from objects
#
SRCS=		$(COMOBJS:%.o=../common/%.c) \
		$(WHATOBJS:%.o=../../whatdir/common/%.c) \
		$(OBJECTS:%.o=../common/%.c)

LIBS =          $(DYNLIB) $(LINTLIB)

# Tune ZDEFS to ignore undefined symbols for building the yacc shared library
# since these symbols (mainly yyparse) are to be resolved elsewhere.
#
$(DYNLIB):= ZDEFS = $(ZNODEFS)
$(DYNLIBCCC):= ZDEFS = $(ZNODEFS)
LINTSRCS=	../common/llib-l$(LIBNAME)

INCLIST=	-I../../include -I../../include/$(MACH)
CPPFLAGS=	$(INCLIST) $(DEFLIST) $(CPPFLAGS.master)
LDLIBS=		$(LDLIBS.cmd)
BUILD.AR=	$(AR) $(ARFLAGS) $@ `$(LORDER) $(OBJS) | $(TSORT)`
LINTFLAGS=	-ax
LINTPOUT=	lintp.out

C99MODE= $(C99_ENABLE)
CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)

$(LINTLIB):=	LINTFLAGS = -nvx
$(ROOTCCSBINPROG):= FILEMODE = 0555

ROOTYACCPAR=	$(YACCPAR:%=$(ROOTCCSBIN)/%)
ROOTLINTDIR=	$(ROOTLIBDIR)
ROOTLINT=	$(LINTSRCS:../common/%=$(ROOTLINTDIR)/%)

DYNLINKLIBDIR=	$(ROOTLIBDIR)
DYNLINKLIB=	$(LIBLINKS:%=$(DYNLINKLIBDIR)/%)

$(DYNLIB) :=	LDLIBS += -lc

DYNFLAGS += -M$(MAPFILE)

CLEANFILES +=	$(LINTPOUT) $(LINTOUT)
CLOBBERFILES +=	$(LIBS) $(LIBRARY)
