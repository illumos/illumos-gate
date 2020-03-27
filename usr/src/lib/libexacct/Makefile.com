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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY =	libexacct.a
VERS =		.1
COMMON_OBJS =	exacct_core.o
LIB_OBJS =	exacct_ops.o
OBJECTS =	$(COMMON_OBJS) $(LIB_OBJS)

include ../../Makefile.lib

SRCS=		$(COMMON_OBJS:%.o=../../../common/exacct/%.c) \
		$(LIB_OBJS:%.o=../common/%.c)

LIBS =		$(DYNLIB)
LDLIBS +=	-lc

SRCDIR =	../common

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	$(CNOWARN_UNINIT)
CPPFLAGS +=	-D_FILE_OFFSET_BITS=64

debug :=	CPPFLAGS += -DLIBEXACCT_DEBUG
debug :=	COPTFLAG = $(CCGDEBUG)
debug :=	COPTFLAG64 = $(CCGDEBUG)

.KEEP_STATE:

all debug: $(LIBS)


include ../../Makefile.targ

objs/%.o pics/%.o: ../../../common/exacct/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
