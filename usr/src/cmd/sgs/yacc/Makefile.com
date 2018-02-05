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
# Copyright 2015 Gary Mills
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		yacc

COMOBJS=	y1.o y2.o y3.o y4.o
POBJECTS=	$(COMOBJS)
POBJS=		$(POBJECTS:%=objs/%)

OBJECTS=	libmai.o libzer.o

LIBRARY=	liby.a
VERS=		.1
YACCPAR=	yaccpar

include ../../../../lib/Makefile.lib

SRCDIR =	../common

# Override default source file derivation rule (in Makefile.lib)
# from objects
#
COMSRCS=	$(COMOBJS:%.o=../common/%.c)
LIBSRCS=	$(OBJECTS:%.o=../common/%.c)
SRCS=		$(COMSRCS) $(LIBSRCS)

LIBS =          $(DYNLIB) $(LINTLIB)

# Append to LINTFLAGS and LINTFLAGS64 from lib/Makefile.lib
LINTFLAGS +=	-erroff=E_NAME_MULTIPLY_DEF2
LINTFLAGS64 +=	-erroff=E_NAME_MULTIPLY_DEF2

# Tune ZDEFS to ignore undefined symbols for building the yacc shared library
# since these symbols (mainly yyparse) are to be resolved elsewhere.
#
$(DYNLIB):= ZDEFS = $(ZNODEFS)
$(DYNLIBCCC):= ZDEFS = $(ZNODEFS)
LINTSRCS=	../common/llib-l$(LIBNAME)
$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)

INCLIST=	-I../../include -I../../include/$(MACH)
CPPFLAGS=	$(INCLIST) $(DEFLIST) $(CPPFLAGS.master)
$(PROG):=	LDLIBS = $(LDLIBS.cmd)
BUILD.AR=	$(AR) $(ARFLAGS) $@ `$(LORDER) $(OBJS) | $(TSORT)`

LINTPOUT=	lint.out

CSTD= $(CSTD_GNU99)
CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized

$(ROOTPROG):= FILEMODE = 0555

ROOTYACCPAR=	$(YACCPAR:%=$(ROOTSHLIBCCS)/%)

ROOTLINTDIR=	$(ROOTLIBDIR)
ROOTLINT=	$(LINTSRCS:../common/%=$(ROOTLINTDIR)/%)

DYNLINKLIBDIR=	$(ROOTLIBDIR)
DYNLINKLIB=	$(LIBLINKS:%=$(DYNLINKLIBDIR)/%)

LDLIBS += -lc

CLEANFILES +=	$(LINTPOUT)
CLOBBERFILES +=	$(LIBS) $(LIBRARY)

lint: lintcheck
