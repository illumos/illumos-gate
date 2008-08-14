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
#

LIBRARY =	libSTK_9840.a
VERS =		.1
OBJS_COMMON =	dm_STK_9840.o
OBJS_SHARED =	dm_9x40_common.o

OBJECTS = 	$(OBJS_COMMON) $(OBJS_SHARED)

include $(SRC)/lib/Makefile.lib
include ../../Makefile.defs

LIBS =		$(DYNLIB) $(LINTLIB)

SRCDIR =	../common

DMDIR = $(SRC)/lib/mms/dm/libcommon

SRCS =	$(OBJS_COMMON:%.o=$(SRCDIR)/%.c)	\
	$(OBJS_SHARED:%.o=$(DMDIR)/%.c)

ROOTLIBDIR = 	$(ROOTMMSDMLIBDIR)

LDLIBS	+=	-lc

CFLAGS +=	$(CCVERBOSE)

CPPFLAGS +=	-DMMS_OPENSSL
CPPFLAGS +=	-I$(SRCDIR) -I$(SRC)/common/mms/mms
CPPFLAGS +=	-I$(SRC)/cmd/mms/dm/common -I../../../mms/common
CPPFLAGS +=	-I$(SRC)/uts/common/io/mms/dda
CPPFLAGS +=	-I$(SRC)/uts/common/io/mms/dmd
CPPFLAGS +=	-I$(SRC)/cmd/mms/wcr/common

.KEEP_STATE:

all: $(LIBS)

lint: $(LINTLIB) lintcheck

pics/%.o: $(DMDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
include ../../Makefile.rootdirs
