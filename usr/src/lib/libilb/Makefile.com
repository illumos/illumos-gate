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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

LIBRARY =	libilb.a
VERS =		.1

LIB_OBJS =	ilb_sg.o ilb_comm.o ilb_subr.o ilb_rules.o
LIB_OBJS +=	ilb_hc.o ilb_nat.o

OBJECTS = 	$(LIB_OBJS)

include ../../Makefile.lib

LIB_SRCS=	$(LIB_OBJS:%.o=$(SRCDIR)/%.c)
LIBS =		$(DYNLIB) $(LINTLIB)
INCS +=		-I../common -I$(SRC)/uts/common
LDLIBS +=	-lc

SRCDIR =	../common
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

CSTD =	$(CSTD_GNU99)

CFLAGS +=	-mt $(CCVERBOSE)
CPPFLAGS +=	$(INCS)
LDLIBS +=	-lsocket

.KEEP_STATE:

all: $(LIBS)

lint: $(LIB_SRCS)
	$(LINT.c) $(LINTCHECKFLAGS) $(LIB_SRCS) $(LDLIBS)

include ../../Makefile.targ
