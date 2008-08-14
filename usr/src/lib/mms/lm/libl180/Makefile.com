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

LIBRARY =	libL180_net.a
VERS =		.1
OBJS_COMMON =	lm_l180.o
OBJS_SHARED =	lm_acs_common.o lm_acs_display.o lm_comm.o lm_lcom.o

OBJECTS = 	$(OBJS_COMMON) $(OBJS_SHARED)

include $(SRC)/lib/Makefile.lib
include ../../Makefile.defs

LIBS =		$(DYNLIB) $(LINTLIB)

SRCDIR =	../common

LMDIR = $(SRC)/lib/mms/lm/libcommon

SRCS =	$(OBJS_COMMON:%.o=$(SRCDIR)/%.c) $(OBJS_SHARED:%.o=$(LMDIR)/%.c)

ROOTLIBDIR = 	$(ROOTMMSLMLIBDIR)

LDLIBS +=	-lc
LDLIBS +=	-L$(SRC)/lib/mms/mms/$(MACH) -lmms

CFLAGS +=	$(CCVERBOSE)

CPPFLAGS +=	-DMMS_OPENSSL
CPPFLAGS +=	-I$(SRCDIR) -I$(SRC)/common/mms/mms
CPPFLAGS +=	-I$(SRC)/cmd/mms/lm/common -I../../../mms/common
CPPFLAGS +=	-I../../libcommon -I$(ACSLSH)
CPPFLAGS +=	-erroff=E_IMPLICIT_DECL_FUNC_RETURN_INT

.KEEP_STATE:

all: $(LIBS)

lint: $(LINTLIB) lintcheck

pics/%.o: $(SRC)/lib/mms/lm/libcommon/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
include ../../Makefile.rootdirs
