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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY =	libilb.a
VERS =		.1

LIB_OBJS =	ilb_sg.o ilb_comm.o ilb_subr.o ilb_rules.o
LIB_OBJS +=	ilb_hc.o ilb_nat.o

# We don't have a userland-accessible implementation of list handling
# so we use the one in uts (filched off libzpool)
LIST_OBJS = 	list.o
OBJECTS = 	$(LIB_OBJS) $(LIST_OBJS)

include ../../Makefile.lib

LIB_SRCS=	$(LIB_OBJS:%.o=$(SRCDIR)/%.c)
LIBS =		$(DYNLIB) $(LINTLIB)
INCS +=		-I../common -I$(SRC)/uts/common
LDLIBS +=	-lc

SRCDIR =	../common
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

C99MODE =	$(C99_ENABLE)

# use for prod:
CFLAGS +=	-mt $(CCVERBOSE)
CPPFLAGS +=	$(INCS)
LDLIBS +=	-lsocket

# use for debug:
CFLAGS +=	-g
STRIP_STABS=	:
CTFCVTFLAGS +=	-g
CTFMERGE_LIB	= $(CTFMERGE) -g -t -f -L VERSION -o $@ $(PICS)
DYNFLAGS +=	-g

.KEEP_STATE:

all: $(LIBS)

lint: $(LIB_SRCS)
	$(LINT.c) $(LINTCHECKFLAGS) $(LIB_SRCS) $(LDLIBS)

include ../../Makefile.targ

# the below is needed to get list.o built
pics/%.o: ../../../uts/common/os/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
